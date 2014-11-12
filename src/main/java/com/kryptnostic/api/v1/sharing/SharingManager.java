package com.kryptnostic.api.v1.sharing;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.crypto.v1.ciphers.AesCryptoService;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.crypto.v1.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.sharing.v1.IncomingShares;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.sharing.v1.SharingRequest;
import com.kryptnostic.sharing.v1.models.PairedEncryptedSearchDocumentKey;
import com.kryptnostic.sharing.v1.models.Share;
import com.kryptnostic.sharing.v1.requests.KeyRegistrationRequest;
import com.kryptnostic.sharing.v1.requests.SharingApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;
import com.kryptnostic.users.v1.UserKey;

public class SharingManager implements SharingClient {
    private static ObjectMapper               mapper     = KodexObjectMapperFactory.getObjectMapper();
    private static DeflatingJacksonMarshaller marshaller = new DeflatingJacksonMarshaller();
    private final DataStore                   dataStore;
    private final KryptnosticConnection       connection;
    private final KryptnosticContext          context;
    private final SharingApi                  sharingApi;

    public SharingManager( KryptnosticConnection connection, KryptnosticContext context, SharingApi sharingClient ) {
        this.dataStore = connection.getDataStore();
        this.connection = connection;
        this.context = context;
        this.sharingApi = sharingClient;
    }

    @Override
    public void shareDocumentWithUsers( DocumentId documentId, Set<UserKey> users ) {

        DataStore dataStore = context.getSecurityService().getDataStore();
        EncryptedSearchSharingKey sharingKey = null;
        BitVector searchNonce = null;
        try {
            sharingKey = marshaller.fromBytes(
                    dataStore.get( ( documentId.getDocumentId() + EncryptedSearchSharingKey.class.getCanonicalName() )
                            .getBytes() ),
                    EncryptedSearchSharingKey.class );
            searchNonce = marshaller.fromBytes(
                    dataStore.get( ( documentId.getDocumentId() + BitVector.class.getCanonicalName() ).getBytes() ),
                    BitVector.class );
        } catch ( IOException e1 ) {
            e1.printStackTrace();
        }

        AesCryptoService service;
        try {
            service = new AesCryptoService( Cypher.AES_CTR_PKCS5_128 );
            Map<UserKey, RsaCompressingEncryptionService> services = context.getEncryptionServiceForUsers( users );
            Map<UserKey, byte[]> seals = Maps.newHashMap();
            for ( Entry<UserKey, RsaCompressingEncryptionService> serviceEntry : services.entrySet() ) {
                seals.put( serviceEntry.getKey(), serviceEntry.getValue().encrypt( service ) );
            }

            byte[] encryptedSharingKey = mapper.writeValueAsBytes( service.encrypt( marshaller.toBytes( sharingKey ) ) );
            byte[] encryptedDocumentKey = mapper
                    .writeValueAsBytes( service.encrypt( marshaller.toBytes( searchNonce ) ) );

            SharingRequest request = new SharingRequest( documentId, seals, encryptedSharingKey, encryptedDocumentKey );
            sharingApi.shareDocument( request );

        } catch (
                NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | SecurityConfigurationException
                | IOException e ) {
            e.printStackTrace();
        }
    }

    public int processIncomingShares() throws IOException, SecurityConfigurationException {
        IncomingShares incoming = sharingApi.getIncomingShares();
        Map<UUID, Share> shares = incoming.getShares();
        RsaCompressingCryptoService service = context.getRsaCryptoService();
        Map<UUID, PairedEncryptedSearchDocumentKey> keys = Maps.newHashMap();
        ;
        for ( Entry<UUID, Share> shareEntry : shares.entrySet() ) {
            Share share = shareEntry.getValue();

            AesCryptoService decryptor = service.decrypt( share.getSeal(), AesCryptoService.class );

            DocumentId id = share.getDocumentId();

            BitVector searchNonce = marshaller
                    .fromBytes( decryptor.decryptBytes( mapper.readValue(
                            share.getEncryptedDocumentKey(),
                            BlockCiphertext.class ) ), BitVector.class );

            EncryptedSearchSharingKey sharingKey = marshaller
                    .fromBytes( decryptor.decryptBytes( mapper.readValue(
                            share.getEncryptedSharingKey(),
                            BlockCiphertext.class ) ), EncryptedSearchSharingKey.class );

            EncryptedSearchDocumentKey documentKey = null;

            try {
                documentKey = new EncryptedSearchDocumentKey(
                        context.encryptNonce( searchNonce ),
                        context.fromSharingKey( sharingKey ),
                        share.getDocumentId() );
            } catch ( IrisException e ) {
                e.printStackTrace();
            }

            PairedEncryptedSearchDocumentKey pairedKey = new PairedEncryptedSearchDocumentKey(
                    share.getDocumentId(),
                    documentKey );

            keys.put( shareEntry.getKey(), pairedKey );
        }
        KeyRegistrationRequest request = new KeyRegistrationRequest( keys );
        sharingApi.registerKeys( request );
        return shares.size();
    }

    @Override
    public void unsharedDocumentWithUsers( DocumentId documentId, Set<UserKey> users ) {

    }
}
