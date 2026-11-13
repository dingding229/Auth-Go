package main

import sdk "authgo/sdk"

// protect validates the original signed authorization deadline at sensitive entry points.
// payload encrypted program code uses payload.unlock and the language loader separately.
func protect(client *sdk.Client, result *sdk.Result) error {
	return client.Validate(result.Ticket())
}
