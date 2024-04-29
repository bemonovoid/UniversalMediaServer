/*
 * This file is part of Universal Media Server, based on PS3 Media Server.
 *
 * This program is a free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2 of the License only.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package net.pms.util;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Function;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.nio.client.methods.HttpAsyncMethods;

/**
 * Download file from the external server and inform the calling process about
 * the progress of download.
 *
 * @author valib
 */
public class UriFileRetriever {

	private final MaliciousURLScanner maliciousURLScanner;

  public UriFileRetriever() {
    this.maliciousURLScanner = new MaliciousURLScannerMock();
  }

  /**
	 * Download file from the external server and return the content of it in
	 * the ByteArray.
	 *
	 * @param uri The URI of the external server file.
	 *
	 * @return the content of the downloaded file.
	 *
	 * @throws IOException
	 */
	public byte[] get(String uri) throws IOException {
		URI uriObject = URI.create(uri);
		String uriScheme = uriObject.getScheme();
		if (!uriScheme.startsWith("http")) {
			throw new IllegalArgumentException(String.format("Unsupported uri scheme. Expected 'http', 'https', but was: %s", uriScheme));
		}
		if (!maliciousURLScanner.scan(uri)) {
			throw new IllegalArgumentException(String.format("Malicious url detected. Resource downloading aborted. %s", uri));
		}
		try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
			httpclient.start();
			HttpGet request = new HttpGet(URLEncoder.encode(uri, StandardCharsets.UTF_8));
			Future<HttpResponse> future = httpclient.execute(request, null);
			HttpResponse response = future.get();
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode != HttpStatus.SC_OK) {
				throw new IOException("HTTP response not OK for " + uriObject.toString());
			}
			Header contentTypeHeader = response.getEntity().getContentType();
			if (contentTypeHeader != null && contentTypeHeader.getElements().length > 0) {
				for (HeaderElement contentTypeHeaderElement : contentTypeHeader.getElements()) {
					String contentType = contentTypeHeaderElement.getValue();
					if (contentType.startsWith("image/")) {
						break;
					}
				}
				throw new IllegalStateException(String.format("Illegal content type of downloaded file. %s resource must be an image", uriObject));
			}
			//TODO Use file parsers like Apache Tika to detect file mime type based on file content. Never rely on content type.

			return IOUtils.toByteArray(response.getEntity().getContent());
		} catch (InterruptedException | ExecutionException e) {
			throw new IOException("Unable to download by HTTP" + e.getMessage());
		}
	}

	/**
	 * Download the file from the external server and store it at the defined
	 * path.
	 *
	 * @param uri The URI of the external server file.
	 * @param file The path to store downloaded file.
	 * @param callback The calling class which will be informed about the
	 *            progress of the file download.
	 *
	 * @throws Exception
	 */
	public void getFile(URI uri, File file, UriRetrieverCallback callback) throws Exception {
		try (CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault()) {
			httpclient.start();
			ZeroCopyConsumerWithCallback<File> consumer = new ZeroCopyConsumerWithCallback<File>(file, uri.toString(), callback) {

				@Override
				protected File process(final HttpResponse response, final File file, final ContentType contentType) throws Exception {
					if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
						throw new ClientProtocolException("Connection to host failed: " + response.getStatusLine());
					}

					return file;
				}
			};

			Future<File> future = httpclient.execute(HttpAsyncMethods.createGet(uri), consumer, null, null);
			file = future.get();
		}
	}

	interface MaliciousURLScanner {
		boolean scan(String uri);
	}

	static class MaliciousURLScannerMock implements MaliciousURLScanner {

		private final Function<String, Boolean> urlScannerEngine;

    MaliciousURLScannerMock() {
      this.urlScannerEngine = uri -> true;
    }

		@Override
    public boolean scan(String uri) {
			return urlScannerEngine.apply(uri);
		}
	}
}
