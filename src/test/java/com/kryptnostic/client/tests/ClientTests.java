package com.kryptnostic.client.tests;

import javax.inject.Inject;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.kryptnostic.api.v1.client.KryptnosticConnection;
import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;

/**
 * Kryptnostic client tests. Primarily testing the functionality of
 * KryptnosticConnection.
 * 
 * @author Nick Hewitt
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(loader=AnnotationConfigContextLoader.class,classes=TestConfiguration.class)
public class ClientTests {
    @Inject
    private KryptnosticConnection kryptnosticConnection;

    @Test
    public void uploadDocumentTest() {
        String document = "We suffer into truth.";
        String id = null;
        try {
            id = kryptnosticConnection.uploadDocument(document);
        } catch (BadRequestException e) {
            e.printStackTrace();
        }
        String retrieved = null;
        try {
            retrieved = kryptnosticConnection.getDocument(id);
        } catch (ResourceNotFoundException e) {
            e.printStackTrace();
        }
        Assert.assertFalse(retrieved == null);
        Assert.assertEquals(retrieved, document);
    }

}
