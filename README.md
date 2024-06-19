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



## Regular auth flow
1. Redirect the user to `https://login.hns.au/auth?return=<return-url>`
2. User logs in and will be returned to `https://<return-url>?username=<username>&token=<token>`
3. Use the token to authenticate the user with `https://login.hns.au/auth/user?token=<token>`  
   This will return the following json:  
   ```json
   {
	"displayName": "Nathan.Woodburn/",
	"email": "contact@nathan.woodburn.au",
	"email_verified": false,
	"family_name": "nathan.woodburn",
	"given_name": "nathan.woodburn",
	"id": 1,
	"links": "https://woodburn",
	"name": "Nathan.Woodburn/",
	"nickname": "Nathan.Woodburn/",
	"picture": "https://nathan.woodburn.au/assets/img/profile.png",
	"preferred_username": "nathan.woodburn",
	"profile": "https://login.hns.au/u/nathan.woodburn",
	"sub": 1,
	"uid": 1,
	"username": "nathan.woodburn",
	"website": "https://nathan.woodburn"
    }
   ```


## Deploy your own instance

```bash
docker volume create hns-login
docker run -d -p 9090:9090 --name hns-login -v hns-login:/app/instance git.woodburn.au/nathanwoodburn/hns-login:latest
```

