/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package javax.websocket;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface Session {

    ClientContainer getContainer();

    void setEncoders(List<Encoder> encoders);

    void addMessageHandler(MessageHandler listener);

    Set<MessageHandler> getMessageHandlers();

    void removeMessageHandler(MessageHandler listener);

    String getProtocolVersion();

    String getNegotiatedSubprotocol();

    List<String> getNegotiatedExtensions();

    boolean isSecure();

    long getInactiveTime();

    boolean isActive();

    long getTimeout();

    void setTimeout(long seconds);

    void setMaximumMessageSize(long length);

    long getMaximumMessageSize();

    RemoteEndpoint getRemote();

    void close() throws IOException;

    void close(CloseReason closeStatus) throws IOException;

    URI getRequestURI();

    Map<String, String[]> getRequestParameterMap();

    String getQueryString();

    Map<String,String> getPathParameters();
}
