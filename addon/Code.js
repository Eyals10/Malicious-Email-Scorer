const BACKEND_URL = 'https://email-scorer-api-727245842620.us-central1.run.app';

/** Runs every time the user opens an email. */
function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);

  let text;
  try {
    const res = UrlFetchApp.fetch(BACKEND_URL + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
      // Trim to the backend's limits, so a huge sender can't make scoring fail.
      payload: JSON.stringify({
        sender: message.getFrom().slice(0, 500),
        subject: message.getSubject().slice(0, 1000),
      }),
      muteHttpExceptions: true,
    });
    if (res.getResponseCode() === 200) {
      const data = JSON.parse(res.getContentText());
      text = 'Score: ' + data.score + ' / 100 (' + data.verdict + ')';
    } else {
      text = 'Backend error ' + res.getResponseCode();
    }
  } catch (err) {
    text = 'Could not reach the backend.';
  }

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(text)))
    .build();
  return [card];
}

/** Run once from the editor: prints the token audience the backend must expect. */
function logTokenAudience() {
  const part = ScriptApp.getIdentityToken().split('.')[1];
  const padded = part + '='.repeat((4 - (part.length % 4)) % 4);
  const claims = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(padded)).getDataAsString());
  console.log('TOKEN_AUDIENCE = ' + claims.aud);
}
