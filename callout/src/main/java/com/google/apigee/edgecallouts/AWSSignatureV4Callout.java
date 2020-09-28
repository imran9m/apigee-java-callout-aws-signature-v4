// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.apigee.edgecallouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.edgecallouts.util.Debug;
import com.google.apigee.edgecallouts.util.VarResolver;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class AWSSignatureV4Callout implements Execution {

    public static final String CALLOUT_VAR_PREFIX = "aws-signature-v4";
    public static final String ENDPOINT_PROP = "endpoint";
    public static final String REGION_PROP = "region";
    public static final String SERVICE_PROP = "service";
    public static final String KEY_PROP = "key";
    public static final String SECRET_PROP = "secret";
    public static final String MESSAGE_VAR_PROP = "message-variable-ref";
    public static final String VERB_PROP = "verb";
    public static final String PATH_PROP = "path";
    public static final String RESOURCE_PROP = "resource";

    public static final String X_AMZ_CONTENT_SHA256 = "x-Amz-content-sha256";
    public static final String X_AMZ_DATE = "X-Amz-Date";
    public static final String AUTHORIZATION = "Authorization";
    public static final String HOST = "Host";

    private static String sha256(String content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
        return DatatypeConverter.printHexBinary(hash).toLowerCase();
    }

    private static Map<String, String> getSignedRequest(Message msg, String endpoint, String region, String service, String key, String secret) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        String verb = msg.getVariable(VERB_PROP);
        String resource = msg.getVariable(PATH_PROP);

        TreeMap<String, String> requestHeaders = new TreeMap<>();
        for (String headerName : msg.getHeaderNames()) {
            List<String> headerValues = msg.getHeaders(headerName);
            for (String headerValue : headerValues) {
                requestHeaders.put(headerName, headerValue);
            }
        }
        TreeMap<String, String> queryParameters = new TreeMap<>();
        for (String queryParamName : msg.getQueryParamNames()) {
            List<String> queryParamValues = msg.getQueryParams(queryParamName);
            for (String queryParamValue : queryParamValues) {
                queryParameters.put(queryParamName, queryParamValue);
            }

        }

        String content = null;
        if (msg.getContent() != null) {
            content = msg.getContent();
        }

        AWSV4Auth awsv4Auth = new AWSV4Auth.Builder(key, secret)
                .regionName(region)
                .serviceName(service)
                .httpMethodName(verb)
                .canonicalURI(resource)
                .queryParametes(queryParameters)
                .awsHeaders(requestHeaders)
                .payload(content)
                .debug()
                .build();

        return awsv4Auth.getHeaders();
    }


    private final Map properties;
    private ByteArrayOutputStream stdoutOS;
    private ByteArrayOutputStream stderrOS;
    private PrintStream stdout;
    private PrintStream stderr;

    public AWSSignatureV4Callout(Map properties) throws UnsupportedEncodingException {
        this.properties = properties;
        this.stdoutOS = new ByteArrayOutputStream();
        this.stderrOS = new ByteArrayOutputStream();
        this.stdout = new PrintStream(stdoutOS, true, StandardCharsets.UTF_8.name());
        this.stderr = new PrintStream(stderrOS, true, StandardCharsets.UTF_8.name());
    }

    private void saveOutputs(MessageContext msgCtx) {
        msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stdout", new String(stdoutOS.toByteArray(), StandardCharsets.UTF_8));
        msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stderr", new String(stderrOS.toByteArray(), StandardCharsets.UTF_8));
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {

            VarResolver vars = new VarResolver(messageContext, properties);
            Debug dbg = new Debug(messageContext, CALLOUT_VAR_PREFIX);

            Boolean debug = vars.getProp("debug", Boolean.class, false);

            String endpoint = vars.getProp(ENDPOINT_PROP);
            String region = vars.getProp(REGION_PROP);
            String service = vars.getProp(SERVICE_PROP);
            String key = vars.getProp(KEY_PROP);
            String secret = vars.getProp(SECRET_PROP);
            String messageVariable = vars.getProp(MESSAGE_VAR_PROP);
            Message msg = (Message) messageContext.getVariable(messageVariable);

            if (msg == null) {
                throw new Exception("Could not resolve message object \"" + messageVariable + "\"");
            }

            String verb = (String) msg.getVariable(VERB_PROP);
            String resource = (String) msg.getVariable(PATH_PROP);


            Map<String, String> headers = getSignedRequest(msg, endpoint, region, service, key, secret);

            if (debug) {
                dbg.setVar(VERB_PROP, verb);
                dbg.setVar(ENDPOINT_PROP, endpoint);
                dbg.setVar(RESOURCE_PROP, resource);
                dbg.setVar(REGION_PROP, region);
                dbg.setVar(SERVICE_PROP, service);
                dbg.setVar(KEY_PROP, key);
                dbg.setVar(SECRET_PROP, secret);
            }

            for (Map.Entry<String, String> headerEntry : headers.entrySet()) {
                String headerName = headerEntry.getKey();
                if (headerName.equalsIgnoreCase(AUTHORIZATION) ||
                        headerName.equalsIgnoreCase(X_AMZ_DATE) ||
                        headerName.equalsIgnoreCase(X_AMZ_CONTENT_SHA256) ||
                        headerName.equalsIgnoreCase(HOST)) {
                    msg.setHeader(headerName, headerEntry.getValue());
                }
            }

            return ExecutionResult.SUCCESS;

        } catch (Error | Exception e) {
            e.printStackTrace(stderr);
            return ExecutionResult.ABORT;
        } finally {
            saveOutputs(messageContext);
        }
    }
}