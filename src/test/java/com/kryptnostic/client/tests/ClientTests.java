package com.kryptnostic.client.tests;

import javax.inject.Inject;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;

/**
 * Kryptnostic client tests. Primarily testing the functionality of KryptnosticConnection.
 * 
 * @author Nick Hewitt
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = TestConfiguration.class)
public class ClientTests {
    @Inject
    private KryptnosticContext kryptnosticContext;

    @Test
    public void uploadDocumentGetDocumentTest() {
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

    @Test
    public void updateDocumentTest() {
        String document = "what is best in life? the wind in your hair. falcons at your wrist.";
        String id = null;
        try {
            id = kryptnosticContext.uploadDocument(document);
        } catch (BadRequestException e) {
            e.printStackTrace();
        }
        String newDocument = "what is best in life? To crush your enemies, see them driven before you, and to hear the lamentation of the loved ones.";
        try {
            kryptnosticContext.updateDocument(id, newDocument);
        } catch (ResourceNotFoundException e1) {
            e1.printStackTrace();
        }
        
        String retrieved = null;
        try {
            retrieved = kryptnosticContext.getDocument(id);
        } catch (ResourceNotFoundException e) {
            e.printStackTrace();
        }
        Assert.assertFalse(retrieved == null);
        Assert.assertEquals(retrieved, newDocument);
    }
}
