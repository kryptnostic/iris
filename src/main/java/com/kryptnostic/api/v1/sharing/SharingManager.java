package com.kryptnostic.api.v1.sharing;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.sharing.v1.models.IncomingShares;
import com.kryptnostic.sharing.v1.models.Share;
import com.kryptnostic.sharing.v1.models.request.RevocationRequest;
import com.kryptnostic.sharing.v1.models.request.SharingRequest;
import com.kryptnostic.storage.v1.models.EncryptedSearchObjectKey;

public class SharingManager implements SharingClient {
    private static final Logger               logger     = LoggerFactory.getLogger( SharingManager.class );
    private static ObjectMapper               mapper     = KodexObjectMapperFactory.getObjectMapper();
    private final KryptnosticContext          context;
    private final SharingApi                  sharingApi;

    public SharingManager( KryptnosticContext context, SharingApi sharingClient ) {
        this.context = context;
        this.sharingApi = sharingClient;
    }

    @Override
    public void shareObjectWithUsers( String objectId, Set<UUID> users , byte[] sharingPair ) throws ResourceNotFoundException {
        CryptoServiceLoader loader = context.getConnection().getCryptoServiceLoader();

        CryptoService service;
        try {
            Optional<CryptoService> maybeService = loader.get( objectId );
            if ( maybeService.isPresent() ) {
                service = maybeService.get();
                Map<UUID, RsaCompressingEncryptionService> services = context.getEncryptionServiceForUsers( users );
                Map<UUID, byte[]> seals = Maps.newHashMap();
                for ( Entry<UUID, RsaCompressingEncryptionService> serviceEntry : services.entrySet() ) {
                    seals.put( serviceEntry.getKey(), serviceEntry.getValue().encrypt( service ) );
                }

                byte[] encryptedSharingKey = mapper
                        .writeValueAsBytes( service.encrypt( sharingPair ) );

                SharingRequest request = new SharingRequest( objectId, seals, encryptedSharingKey );
                sharingApi.share( request );

            } else {
                logger.error( "Unable to load crypto service for object {}", objectId );
                throw new SecurityConfigurationException( "Failed to load crypto service for object " + objectId );
            }

        } catch ( SecurityConfigurationException | IOException | ExecutionException e ) {
            logger.error( "Failured while sharing object {} with users {}", objectId, users );

        }
    }

    @Override
    public int processIncomingShares() throws IOException, SecurityConfigurationException {
        CryptoServiceLoader loader = context.getConnection().getCryptoServiceLoader();
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return 0;
        }
        Set<byte[]> keys = Sets.newHashSet();

        for ( Share share : incomingShares ) {
            String id = share.getObjectId();
            CryptoService decryptor;
            try {
                logger.info( "Processing share for {}", id );
                Optional<CryptoService> maybeService = loader.get( id );
                if ( maybeService.isPresent() ) {
                    decryptor = maybeService.get();
                } else {
                    logger.error( "Unable to retrieve crypto service for object {}", share.getObjectId() );
                    throw new SecurityConfigurationException( "Unable to retrieve crypto service for object {}"
                            + share.getObjectId() );
                }
            } catch ( ExecutionException e ) {
                throw new IOException( e );
            }
            byte[] sharingPair = null;
            try {
                sharingPair = decryptor.decryptBytes( mapper.readValue(
                        share.getEncryptedSharingKey(),
                        BlockCiphertext.class ) );
            } catch ( NegativeArraySizeException e ) {
                e.printStackTrace();
            }

            keys.add( sharingPair );
        }
//        KeyRegistrationRequest request = new KeyRegistrationRequest( keys );
        sharingApi.addSharingPairs( keys );
        return incomingShares.size();
    }

    @Override
    public void unshareObjectWithUsers( String objectId, Set<UUID> users ) {
        RevocationRequest revocation = new RevocationRequest( objectId, users );
        sharingApi.revokeAccess( revocation );
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
