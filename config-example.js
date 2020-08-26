{
  // Note: Do NOT keep these comments, they will cause an error and are only for the description of fields.
  // Note: The .js extension is to make the formatting work, rename this to config.json when done.
  "port":8888, // HTTP Server port. Required.
  "discord-hook":"https://discord.com/api/webhooks/xxxxxxxxxxx/xxxxxxxxxxx", // Discord error logging hook, leave empty to not log. Optional.
  "hook-secret":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // GitHub webhook secret, used for automatic deployment. Only use type application/json hooks, and only the `push` event.
  "name":"ScratchVerifier", // Instance owner / ID. Included in the error message from the Discord webhook.
  "admins":["user1", "user2"] // LOWERCASE usernames of people with access to the /admin API's and /site/admin features.
}
