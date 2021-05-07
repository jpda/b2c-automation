# b2c-automation

automating b2c tenant creation is not yet available via api.

All other tasks are available via Microsoft Graph.

## prerequisites

The quickest way in will be to use the app with the included registration. If, however, you would rather register your own app to drive this experience, you'll need two main permissions:

`Application.ReadWrite.All` - this lets the app register applications
`DelegatedPermissionGrant.ReadWrite.All` - this lets the app admin consent to your API's scope for your client. This is a _very_ high privilege so you may not be able to do this directly. If you are the creator/owner of the b2c directory, your user account should have permission to do this.