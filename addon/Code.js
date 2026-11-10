const BACKEND_URL = 'https://email-scorer-api-727245842620.us-central1.run.app';

const COLORS = { Safe: '#188038', Suspicious: '#E37400', Malicious: '#D93025' };
const ADVICE = {
  Safe: 'Low risk. Stay alert anyway.',
  Suspicious: "Be careful: don't click links or open attachments unless you trust the sender.",
  Malicious: "Likely phishing. Don't click links, open attachments or reply. Report it as phishing in Gmail.",
};

/** Runs every time the user opens an email. */
function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);
  return [buildCard(analyze(message))];
}

/** Sends the email to the backend. Returns its result, or {error} if scoring failed. */
function analyze(message) {
  try {
    const res = UrlFetchApp.fetch(BACKEND_URL + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
      payload: JSON.stringify(emailData(message)),
      muteHttpExceptions: true,
    });
    if (res.getResponseCode() === 200) return JSON.parse(res.getContentText());
    return { error: 'The scorer answered with error ' + res.getResponseCode() + '.' };
  } catch (err) {
    return { error: 'The scorer could not be reached.' };
  }
}

/** The parts of the email the backend checks, trimmed to its limits so a huge email still gets scored. */
function emailData(message) {
  return {
    sender: message.getFrom().slice(0, 500),
    subject: message.getSubject().slice(0, 1000),
    reply_to: message.getReplyTo().slice(0, 500),
    auth_results: message.getHeader('Authentication-Results').slice(0, 5000),
    html_body: message.getBody().slice(0, 200000),
    attachments: message.getAttachments({ includeInlineImages: false })
      .slice(0, 100)
      .map((a) => a.getName().slice(0, 255)),
  };
}

function buildCard(result) {
  const section = CardService.newCardSection();
  if (result.error) {
    // Never show "Safe" when we couldn't check: failure is not a clean bill of health.
    section.addWidget(paragraph('<b>Could not check this email.</b> ' + escapeHtml(result.error) +
      ' Treat its links and attachments with care.'));
  } else {
    section.addWidget(paragraph('<font color="' + COLORS[result.verdict] + '"><b>' + result.verdict +
      '</b></font> · risk score ' + result.score + ' / 100'));
    const reasons = result.reasons.length
      ? result.reasons.map((r) => '• ' + escapeHtml(r)).join('<br>')
      : 'No warning signs found.';
    section.addWidget(paragraph(reasons));
    section.addWidget(paragraph('<i>' + ADVICE[result.verdict] + '</i>'));
  }
  return CardService.newCardBuilder().addSection(section).build();
}

/** One block of card text. The invisible left-to-right mark (\u200E) ending each line keeps
 *  the final period on the right when Gmail's interface is right-to-left (Hebrew, Arabic). */
function paragraph(html) {
  return CardService.newTextParagraph().setText(html.replace(/<br>/g, '\u200E<br>') + '\u200E');
}

/** Reasons quote attacker-written text (domains, file names), so it must not be read as card formatting. */
function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Run once from the editor: prints the token audience the backend must expect. */
function logTokenAudience() {
  const part = ScriptApp.getIdentityToken().split('.')[1];
  const padded = part + '='.repeat((4 - (part.length % 4)) % 4);
  const claims = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(padded)).getDataAsString());
  console.log('TOKEN_AUDIENCE = ' + claims.aud);
}
