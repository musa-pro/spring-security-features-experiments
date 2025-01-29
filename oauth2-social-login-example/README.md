# Spring OAuth2 Social Login as IDP in Auth Server

The client here uses authorization_code grant type

### Authorization Server
http://localhost:8080/

### Resource Server
http://localhost:8081/

### Test Client Application
This uses Spring Security OAuth2 RestClient  
http://localhost:8082/

Reference Documents & Guides:
- [RestClient Support for OAuth2 in Spring Security 6.4](https://spring.io/blog/2024/10/28/restclient-support-for-oauth2-in-spring-security-6-4)
- [Spring Security 6.4: RestClient Support for OAuth2](https://www.youtube.com/watch?v=nFKcJDpUuZ8)

Invoking to client application will call the resource server using the client credentials grant type.
Thus if you hit http://localhost:8082/client-hello-endpoint, it will call the resource server and return the response.  
But before that, you need to get the access token from the authorization server.
