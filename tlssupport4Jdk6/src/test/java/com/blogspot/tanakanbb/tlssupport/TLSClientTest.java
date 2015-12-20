package com.blogspot.tanakanbb.tlssupport;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;

import javax.net.ssl.HttpsURLConnection;

public class TLSClientTest {

    private static final Charset RESPONSE_CHARSET = Charset.forName("shift_jis");

    private static final String REQUEST_URL = "https://www.google.co.jp/";

    /**
     * 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        String httpsURL = REQUEST_URL;
        URL myurl = new URL(httpsURL);

        HttpsURLConnection con = (HttpsURLConnection) myurl.openConnection();
        con.setSSLSocketFactory(new TLSSocketConnectionFactory());
        InputStream ins = con.getInputStream();

        InputStreamReader isr = new InputStreamReader(ins, RESPONSE_CHARSET);
        BufferedReader in = new BufferedReader(isr);

        String inputLine;

        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
        }

        in.close();
    }
}
