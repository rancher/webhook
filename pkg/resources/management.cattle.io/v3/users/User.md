## Validation Checks

### Update and Delete

When a user is updated or deleted, a check occurs to ensure that the user making the request has permissions greater than or equal to the user being updated or deleted. To get the user's groups, the user's UserAttributes are checked. This is best effort, because UserAttributes are only updated when a User logs in, so it may not be perfectly up to date.

If the user making the request has the verb `manage-users` for the resource `users`, then it is allowed to bypass the check. Note that the wildcard `*` includes the `manage-users` verb.

### Invalid Fields - Update

Users can update the following fields if they had not been set. But after getting initial values, the fields cannot be changed:

- UserName
