package de.danoeh.antennapod.net.common;

import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.NonNull;
import de.danoeh.antennapod.model.download.ProxyConfig;
import de.danoeh.antennapod.net.ssl.SslClientSetup;
import okhttp3.Cache;
import okhttp3.Credentials;
import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import java.security.cert.CertificateException;
import java.io.File;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Provides access to a HttpClient singleton.
 */
public class AntennapodHttpClient {
    private static final String TAG = "AntennapodHttpClient";
    private static final int CONNECTION_TIMEOUT = 10000;
    private static final int READ_TIMEOUT = 30000;
    private static final int MAX_CONNECTIONS = 8;
    private static File cacheDirectory;
    private static ProxyConfig proxyConfig;

    private static volatile OkHttpClient httpClient = null;

    private AntennapodHttpClient() {

    }

    /**
     * Returns the HttpClient singleton.
     */
    public static synchronized OkHttpClient getHttpClient() {
        if (httpClient == null) {
            httpClient = newBuilder().build();
        }
        return httpClient;
    }

    public static synchronized void reinit() {
        httpClient = newBuilder().build();
    }

    /**
     * Creates a new HTTP client.  Most users should just use
     * getHttpClient() to get the standard AntennaPod client,
     * but sometimes it's necessary for others to have their own
     * copy so that the clients don't share state.
     * @return http client
     */
    @NonNull
    public static OkHttpClient.Builder newBuilder() {
        Log.d(TAG, "Creating new instance of HTTP client");

        System.setProperty("http.maxConnections", String.valueOf(MAX_CONNECTIONS));

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.interceptors().add(new BasicAuthorizationInterceptor());
        builder.networkInterceptors().add(new UserAgentInterceptor());

        // set cookie handler
        CookieManager cm = new CookieManager();
        cm.setCookiePolicy(CookiePolicy.ACCEPT_ORIGINAL_SERVER);
        builder.cookieJar(new JavaNetCookieJar(cm));

        // set timeouts
        builder.connectTimeout(CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS);
        builder.readTimeout(READ_TIMEOUT, TimeUnit.MILLISECONDS);
        builder.writeTimeout(READ_TIMEOUT, TimeUnit.MILLISECONDS);
        builder.cache(new Cache(cacheDirectory, 20L * 1000000)); // 20MB

        // configure redirects
        builder.followRedirects(true);
        builder.followSslRedirects(true);

        if (proxyConfig != null && proxyConfig.type != Proxy.Type.DIRECT && !TextUtils.isEmpty(proxyConfig.host)) {
            int port = proxyConfig.port > 0 ? proxyConfig.port : ProxyConfig.DEFAULT_PORT;
            SocketAddress address = InetSocketAddress.createUnresolved(proxyConfig.host, port);
            builder.proxy(new Proxy(proxyConfig.type, address));
            if (!TextUtils.isEmpty(proxyConfig.username) && proxyConfig.password != null) {
                builder.proxyAuthenticator((route, response) -> {
                    String credentials = Credentials.basic(proxyConfig.username, proxyConfig.password);
                    return response.request().newBuilder()
                            .header("Proxy-Authorization", credentials)
                            .build();
                });
            }
        }

        SslClientSetup.installCertificates(builder);

        /**
         * Source: https://stackoverflow.com/a/25992879
         * License: https://creativecommons.org/licenses/by-sa/4.0/
         * Author: sonxurxo
         * This code has been modified from the original
         */
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();


            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder;
    }

    public static void setCacheDirectory(File cacheDirectory) {
        AntennapodHttpClient.cacheDirectory = cacheDirectory;
    }

    public static void setProxyConfig(ProxyConfig proxyConfig) {
        AntennapodHttpClient.proxyConfig = proxyConfig;
    }
}
