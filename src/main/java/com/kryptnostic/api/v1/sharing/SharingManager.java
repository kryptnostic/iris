package com.kryptnostic.api.v1.sharing;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.indexing.v1.ServerIndexPair;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.sharing.v1.models.IncomingShares;
import com.kryptnostic.sharing.v1.models.Share;
import com.kryptnostic.sharing.v1.models.request.RevocationRequest;
import com.kryptnostic.sharing.v1.models.request.SharingRequest;

public class SharingManager implements SharingClient {
    private static final Logger      logger = LoggerFactory.getLogger( SharingManager.class );
    private final KryptnosticContext context;
    private final SharingApi         sharingApi;
    private final KryptnosticEngine  engine;

    public SharingManager( KryptnosticContext context, SharingApi sharingClient, KryptnosticEngine engine ) {
        this.context = context;
        this.sharingApi = sharingClient;
        this.engine = engine;
    }

    @Override
    public Optional<byte[]> getIndexPair( String objectId ) {
        return sharingApi.getIndexPair( objectId );
    }

    @Override
    public Optional<byte[]> getSharingPair( String objectId ) throws ResourceNotFoundException {
        Optional<byte[]> maybeIndexPair = getIndexPair( objectId );
        if ( maybeIndexPair.isPresent() ) {
            return Optional.of( context
                    .getConnection()
                    .getKryptnosticEngine()
                    .getObjectSharingPair( maybeIndexPair.get() ) );
        } else {
            return Optional.absent();
        }
    }

    @Override
    public void shareObjectWithUsers( String objectId, Set<UUID> users ) throws ResourceNotFoundException {
        shareObjectWithUsers( objectId, users, getSharingPair( objectId ) );
    }

    @Override
    public void shareObjectWithUsers( String objectId, Set<UUID> users, Optional<byte[]> sharingPair )
            throws ResourceNotFoundException {
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

                Optional<BlockCiphertext> encryptedSharingPair;
                if ( sharingPair.isPresent() ) {
                    encryptedSharingPair = Optional.of( service.encrypt( sharingPair.get() ) );
                } else {
                    encryptedSharingPair = Optional.absent();
                }
                SharingRequest request = new SharingRequest( objectId, Optional.of( "" ), seals, encryptedSharingPair );
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
    public Set<String> processIncomingShares() throws IOException, SecurityConfigurationException {
        CryptoServiceLoader loader = context.getConnection().getCryptoServiceLoader();
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return ImmutableSet.of();
        }
        Map<String, ServerIndexPair> indexPairs = Maps.newHashMap();

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

            Optional<BlockCiphertext> encryptedSharingPair = share.getEncryptedSharingPair();
            if( encryptedSharingPair.isPresent() ) {
                byte[] sharingPair = decryptor.decryptBytes( encryptedSharingPair.get() );
                Preconditions.checkState( sharingPair.length == 2064 , "Sharing pair must be 2064 bytes long.");
                indexPairs.put( id, new ServerIndexPair( this.engine.getObjectIndexPairFromSharing( sharingPair ) ) );
            }
        }

        sharingApi.addIndexPairs( indexPairs );
        return indexPairs.keySet();
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

}
