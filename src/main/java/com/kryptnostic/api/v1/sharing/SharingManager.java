package com.kryptnostic.api.v1.sharing;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
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
    private final KryptnosticContext          context;
    private final SharingApi                  sharingApi;

    public SharingManager( KryptnosticContext context, SharingApi sharingClient ) {
        this.context = context;
        this.sharingApi = sharingClient;
    }

    @Override
    public void shareDocumentWithUsers( CryptoServiceLoader loader, DocumentId documentId, Set<UserKey> users ) {

        DataStore dataStore = context.getConnection().getDataStore();
        EncryptedSearchSharingKey sharingKey = null;
        try {
            sharingKey = marshaller.fromBytes(
                    dataStore.get( documentId.getDocumentId(), EncryptedSearchSharingKey.class.getCanonicalName() ),
                    EncryptedSearchSharingKey.class );
        } catch ( IOException e1 ) {
            e1.printStackTrace();
        }

        AesCryptoService service;
        try {
            service = (AesCryptoService) loader.get( documentId.getDocumentId() );
            Map<UserKey, RsaCompressingEncryptionService> services = context.getEncryptionServiceForUsers( users );
            Map<UserKey, byte[]> seals = Maps.newHashMap();
            for ( Entry<UserKey, RsaCompressingEncryptionService> serviceEntry : services.entrySet() ) {
                seals.put( serviceEntry.getKey(), serviceEntry.getValue().encrypt( service ) );
            }

            byte[] encryptedSharingKey = mapper.writeValueAsBytes( service.encrypt( marshaller.toBytes( sharingKey ) ) );

            SharingRequest request = new SharingRequest( documentId, seals, encryptedSharingKey );
            sharingApi.shareDocument( request );

        } catch ( SecurityConfigurationException | IOException | ExecutionException e ) {
            e.printStackTrace();
        }
    }

    @Override
    public int processIncomingShares( CryptoServiceLoader loader ) throws IOException, SecurityConfigurationException {
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return 0;
        }
        Set<EncryptedSearchDocumentKey> keys = Sets.newHashSet();

        for ( Share share : incomingShares ) {
            DocumentId id = share.getDocumentId();
            AesCryptoService decryptor;
            try {
                logger.info( "Processing share for {}", id.getDocumentId() );
                decryptor = (AesCryptoService) loader.get( id.getDocumentId() );
            } catch ( ExecutionException e ) {
                throw new IOException( e );
            }

            EncryptedSearchSharingKey sharingKey = marshaller
                    .fromBytes( decryptor.decryptBytes( mapper.readValue(
                            share.getEncryptedSharingKey(),
                            BlockCiphertext.class ) ), EncryptedSearchSharingKey.class );

            EncryptedSearchDocumentKey documentKey = null;

            try {
                documentKey = new EncryptedSearchDocumentKey(
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

    @Override
    public int getIncomingSharesCount() {
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return 0;
        }
        return incomingShares.size();
    }
}
