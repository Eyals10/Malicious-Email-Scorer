const BACKEND_URL = 'https://email-scorer-api-727245842620.us-central1.run.app';

const VERDICTS = {
  Safe: { color: '#188038', icon: 'verified_user', title: 'Looks safe',
          advice: 'Low risk. Stay alert anyway.' },
  Suspicious: { color: '#E37400', icon: 'warning', title: 'Be careful',
                advice: "Don't click links or open attachments unless you trust the sender." },
  Malicious: { color: '#D93025', icon: 'gpp_bad', title: 'Likely phishing',
               advice: "Don't click links, open attachments or reply. Report it as phishing in Gmail." },
};
const GROUP_ICONS = { auth: 'mail_lock', identity: 'person_alert', links: 'link', attachments: 'attach_file' };

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
  const card = CardService.newCardBuilder();
  if (result.error) {
    // Never show "Safe" when we couldn't check: failure is not a clean bill of health.
    return card.addSection(CardService.newCardSection().addWidget(row('error',
      '<b>Could not check this email</b>', escapeHtml(result.error) + ' Treat its links and attachments with care.')))
      .build();
  }
  const v = VERDICTS[result.verdict];

  // 1. Gauge + verdict
  const top = CardService.newCardSection()
    .addWidget(CardService.newImage()
      .setImageUrl(BACKEND_URL + '/gauge/' + result.score + '.gif')
      .setAltText('Risk score ' + result.score + ' out of 100'))
    .addWidget(row(v.icon, '<font color="' + v.color + '"><b>' + v.title + '</b></font>',
      result.verdict + ' · risk score ' + result.score + ' / 100'));
  if (!result.reasons.length) top.addWidget(row('check_circle', 'No warning signs found.'));
  card.addSection(top);

  // 2. Why: the top reasons, each with an icon for its kind
  if (result.reasons.length) {
    const why = CardService.newCardSection().setHeader('Why we flagged it');
    result.reasons.forEach((r) => why.addWidget(row(GROUP_ICONS[r.group], escapeHtml(r.text))));
    card.addSection(why);
  }

  // 3. What to do
  card.addSection(CardService.newCardSection().setHeader('What to do').addWidget(row('lightbulb', v.advice)));

  // 4. Every finding with its points, folded away
  if (result.signals.length > result.reasons.length) {
    const all = CardService.newCardSection()
      .setHeader('All findings (' + result.signals.length + ')')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);
    result.signals.forEach((s) => all.addWidget(row(GROUP_ICONS[s.group], escapeHtml(s.reason), '+' + s.points + ' points')));
    card.addSection(all.addWidget(CardService.newTextParagraph()
      .setText('<i>Each kind of check has a points cap, so the score can be lower than the sum.</i>')));
  }
  return card.build();
}

/** One line of the card: an icon, the text and an optional small grey line under it. */
function row(icon, text, bottomLabel) {
  const widget = CardService.newDecoratedText()
    .setStartIcon(CardService.newIconImage().setMaterialIcon(CardService.newMaterialIcon().setName(icon)))
    .setText(text)
    .setWrapText(true);
  return bottomLabel ? widget.setBottomLabel(bottomLabel) : widget;
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
