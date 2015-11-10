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
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.sharing.api.SharingApi;
import com.kryptnostic.v2.sharing.models.IncomingShares;
import com.kryptnostic.v2.sharing.models.RevocationRequest;
import com.kryptnostic.v2.sharing.models.Share;
import com.kryptnostic.v2.sharing.models.SharingRequest;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class SharingManager implements SharingClient {
    private static final Logger            logger = LoggerFactory.getLogger( SharingManager.class );
    private final KryptnosticCryptoManager context;
    private final SharingApi               sharingApi;
    private final KryptnosticConnection    connection;

    public SharingManager( KryptnosticConnection connection ) {
        this.context = connection.newCryptoManager();
        this.sharingApi = connection.getSharingApi();
        this.connection = connection;
    }

    @Override
    public Optional<byte[]> getSearchPair( VersionedObjectKey objectKey ) {
        byte[] objectSearchPair = sharingApi.getSearchPair( objectKey.getObjectId(), objectKey.getVersion() );
        if ( ( objectSearchPair == null ) || ( objectSearchPair.length != 2080 ) ) {
            return Optional.absent();
        }
        return Optional.of( objectSearchPair );
    }

    public Optional<byte[]> getSharingPair( VersionedObjectKey objectKey ) throws ResourceNotFoundException {
        Optional<byte[]> maybeSearchPair = getSearchPair( objectKey );
        if ( maybeSearchPair.isPresent() ) {
            return Optional.of( connection
                    .getKryptnosticEngine()
                    .getObjectSharePairFromObjectSearchPair( maybeSearchPair.get() ) );
        } else {
            return Optional.absent();
        }
    }

    @Override
    public void shareObjectWithUsers( VersionedObjectKey objectId, Set<UUID> users ) throws ResourceNotFoundException {
        shareObjectWithUsers( objectId, users, getSharingPair( objectId ) );
    }

    @Override
    public void shareObjectWithUsers( VersionedObjectKey objectId, Set<UUID> users, Optional<byte[]> sharingPair )
            throws ResourceNotFoundException {
        CryptoServiceLoader loader = connection.getCryptoServiceLoader();

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
                SharingRequest request = new SharingRequest( objectId, seals, encryptedSharingPair );
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
    public Set<VersionedObjectKey> processIncomingShares() throws IOException, SecurityConfigurationException {
        CryptoServiceLoader loader = connection.getCryptoServiceLoader();
        IncomingShares incomingShares = sharingApi.getIncomingShares();
        if ( incomingShares == null || incomingShares.isEmpty() ) {
            return ImmutableSet.of();
        }
        Map<VersionedObjectKey, ObjectSearchPair> objectSearchPairs = Maps.newHashMap();

        for ( Share share : incomingShares.values() ) {
            VersionedObjectKey id = share.getObjectId();
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
            if ( encryptedSharingPair.isPresent() ) {
                byte[] sharePair = decryptor.decryptBytes( encryptedSharingPair.get() );
                Preconditions.checkState( sharePair.length == KryptnosticEngine.SHARE_PAIR_LENGTH,
                        "Sharing pair must be 2064 bytes long." );
                objectSearchPairs.put( id,
                        new ObjectSearchPair( connection
                                .getKryptnosticEngine()
                                .getObjectSearchPairFromObjectSharePair( sharePair ) ) );
            }
        }

        sharingApi.addSearchPairs( objectSearchPairs );
        return objectSearchPairs.keySet();
    }

    @Override
    public void unshareObjectWithUsers( VersionedObjectKey objectId, Set<UUID> users ) {
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
