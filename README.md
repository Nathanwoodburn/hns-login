# varo-openid

## Add a client
Go to /create-client and add a new client.

Set the following parameters:  

Allowed Scope: `profile`  
Allowed Grant Types: `authorization_code`  
Allowed Response Types: `code`  
Token Endpoint Authentication Method: `client_secret_post`

## Client settings
Set the following parameters:  
`Client ID`: Given by the previous step  
`Client Secret`: Given by the previous step  
`Authorization URL`: `https://login.hns.au/oauth/authorize`  
`Token URL`: `https://login.hns.au/oauth/token`  
`Userinfo URL`: `https://login.hns.au/api/me`  




## Deploy your own instance

```bash
docker volume create hns-login
docker run -d -p 9090:9090 --name hns-login -v hns-login:/app/instance git.woodburn.au/nathanwoodburn/hns-login:latest
```

