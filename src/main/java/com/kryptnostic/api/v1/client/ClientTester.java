package com.kryptnostic.api.v1.client;


public class ClientTester {

    private static final String URL = "http://localhost:8081/rhizome/v1";

    public static void main(String[] args) {
        DefaultKryptnosticConnection conn = new DefaultKryptnosticConnection(URL);

        String document = "I am so cool";
        
        String docid = conn.uploadDocument(document);
        
        System.out.println(conn.getDocument(docid));

    }
}
