package com.kryptnostic.api.v1.sharing;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.sharing.v1.models.DocumentId;
import com.kryptnostic.sharing.v1.models.IncomingShares;
import com.kryptnostic.sharing.v1.models.Share;
import com.kryptnostic.sharing.v1.models.request.KeyRegistrationRequest;
import com.kryptnostic.sharing.v1.models.request.SharingRequest;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;

public class SharingManager implements SharingClient {
    private static final Logger               logger     = LoggerFactory.getLogger( SharingManager.class );
    private static ObjectMapper               mapper     = KodexObjectMapperFactory.getObjectMapper();
    private static DeflatingJacksonMarshaller marshaller = new DeflatingJacksonMarshaller();
    private final DataStore                   dataStore;
    private final KryptnosticConnection       connection;
    private final KryptnosticContext          context;
    private final SharingApi                  sharingApi;

    public SharingManager( KryptnosticContext context, SharingApi sharingClient ) {
        this.connection = context.getConnection();
        this.dataStore = connection.getDataStore();
        this.context = context;
        this.sharingApi = sharingClient;
    }

    @Override
    public void shareDocumentWithUsers( DocumentId documentId, Set<UserKey> users ) {

        DataStore dataStore = context.getConnection().getDataStore();
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

    @Override
    public int processIncomingShares() throws IOException, SecurityConfigurationException {
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        RsaCompressingCryptoService service = context.getRsaCryptoService();
        Set<EncryptedSearchDocumentKey> keys = Sets.newHashSet();
        ;
        for ( Share share : incomingShares ) {
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
                logger.error(
                        "Unable to create encrypted search document key for document: {}",
                        share.getDocumentId(),
                        e );
            }

            keys.add( documentKey );
        }
        KeyRegistrationRequest request = new KeyRegistrationRequest( keys );
        sharingApi.registerKeys( request );
        return incomingShares.size();
    }

    @Override
    public void unsharedDocumentWithUsers( DocumentId documentId, Set<UserKey> users ) {

    }
}
