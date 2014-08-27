package com.kryptnostic.client.tests;

import javax.inject.Inject;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.kryptnostic.api.v1.client.KryptnosticContext;
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
    private KryptnosticContext kryptnosticContext;

    @Test
    public void uploadDocumentTest() {
        String document = "lo and behold.";
        String id = null;
        try {
            id = kryptnosticContext.uploadDocument(document);
        } catch (BadRequestException e) {
            e.printStackTrace();
        }
        String retrieved = null;
        try {
            retrieved = kryptnosticContext.getDocument(id);
        } catch (ResourceNotFoundException e) {
            e.printStackTrace();
        }
        Assert.assertFalse(retrieved == null);
        Assert.assertEquals(retrieved, document);
    }

}
