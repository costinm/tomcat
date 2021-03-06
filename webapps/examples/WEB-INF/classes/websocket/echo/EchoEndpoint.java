/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package websocket.echo;

import javax.websocket.DefaultServerConfiguration;
import javax.websocket.Endpoint;
import javax.websocket.EndpointConfiguration;
import javax.websocket.ServerEndpointConfiguration;
import javax.websocket.Session;

public class EchoEndpoint extends Endpoint{

    private static ServerEndpointConfiguration config =
            new DefaultServerConfiguration("/websocket/echoProgrammatic") {

        @Override
        public boolean checkOrigin(String originHeaderValue) {
            // Accept any
            return true;
        }
    };

    @Override
    public EndpointConfiguration getEndpointConfiguration() {
        return config;
    }

    @Override
    public void onOpen(Session session) {
        // TODO - Review this debug hack
        System.out.println("EchoEndpoint onOpen() called");
        // TODO Auto-generated method stub

    }
}
