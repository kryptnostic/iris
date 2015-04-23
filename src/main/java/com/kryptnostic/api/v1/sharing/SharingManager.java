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
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.directory.v1.principal.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.sharing.v1.models.IncomingShares;
import com.kryptnostic.sharing.v1.models.Share;
import com.kryptnostic.sharing.v1.models.request.KeyRegistrationRequest;
import com.kryptnostic.sharing.v1.models.request.SharingRequest;
import com.kryptnostic.storage.v1.models.EncryptedSearchObjectKey;

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
    public void shareObjectWithUsers( String objectId, Set<UserKey> users ) throws ResourceNotFoundException {
        CryptoServiceLoader loader = context.getConnection().getCryptoServiceLoader();
        EncryptedSearchPrivateKey privKey = context.getConnection().getEncryptedSearchPrivateKey();
        EncryptedSearchBridgeKey bridgeKey = sharingApi.getEncryptedSearchObjectKey( objectId ).getBridgeKey();

        EncryptedSearchSharingKey sharingKey = privKey.calculateSharingKey( bridgeKey );

        AesCryptoService service;
        try {
            service = (AesCryptoService) loader.get( objectId );
            Map<UserKey, RsaCompressingEncryptionService> services = context.getEncryptionServiceForUsers( users );
            Map<UserKey, byte[]> seals = Maps.newHashMap();
            for ( Entry<UserKey, RsaCompressingEncryptionService> serviceEntry : services.entrySet() ) {
                seals.put( serviceEntry.getKey(), serviceEntry.getValue().encrypt( service ) );
            }

            byte[] encryptedSharingKey = mapper.writeValueAsBytes( service.encrypt( marshaller.toBytes( sharingKey ) ) );

            SharingRequest request = new SharingRequest( objectId, seals, encryptedSharingKey );
            sharingApi.share( request );

        } catch ( SecurityConfigurationException | IOException | ExecutionException e ) {
            e.printStackTrace();
        }
    }

    @Override
    public int processIncomingShares() throws IOException, SecurityConfigurationException {
        CryptoServiceLoader loader = context.getConnection().getCryptoServiceLoader();
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return 0;
        }
        Set<EncryptedSearchObjectKey> keys = Sets.newHashSet();

        for ( Share share : incomingShares ) {
            String id = share.getObjectId();
            AesCryptoService decryptor;
            try {
                logger.info( "Processing share for {}", id );
                decryptor = (AesCryptoService) loader.get( id );
            } catch ( ExecutionException e ) {
                throw new IOException( e );
            }
            EncryptedSearchSharingKey sharingKey = null;
            try {
                sharingKey = marshaller.fromBytes( decryptor.decryptBytes( mapper.readValue(
                        share.getEncryptedSharingKey(),
                        BlockCiphertext.class ) ), EncryptedSearchSharingKey.class );
            } catch ( NegativeArraySizeException e ) {
                e.printStackTrace();
            }

            if ( sharingKey == null ) {
                logger.error( "Null sharing key for object {}", id );
                continue;
            }

            EncryptedSearchObjectKey searchKey = null;

            try {
                searchKey = new EncryptedSearchObjectKey( context.fromSharingKey( sharingKey ), share.getObjectId() );
            } catch ( IrisException e ) {
                logger.error( "Unable to create encrypted search key for object: {}", share.getObjectId(), e );
            }

            keys.add( searchKey );
        }
        KeyRegistrationRequest request = new KeyRegistrationRequest( keys );
        sharingApi.registerKeys( request );
        return incomingShares.size();
    }

    @Override
    public void unshareObjectWithUsers( String objectId, Set<UserKey> users ) {

    }

    @Override
    public int getIncomingSharesCount() {
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return 0;
        }
        return incomingShares.size();
    }

    @Override
    public EncryptedSearchObjectKey getObjectKey( String objectId ) throws ResourceNotFoundException {
        return sharingApi.getEncryptedSearchObjectKey( objectId );
    }
}
