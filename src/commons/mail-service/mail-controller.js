const MailerService = require("./mail-service");
const BookingManager = require("../data-managers/booking-manager");
const { BookableManager } = require("../data-managers/bookable-manager");
const EventManager = require("../data-managers/event-manager");
const TenantManager = require("../data-managers/tenant-manager");
const InstanceManager = require("../data-managers/instance-manager");
const bunyan = require("bunyan");
const PaymentUtils = require("../utilities/payment-utils");
const UserManager = require("../data-managers/user-manager");
const QRCode = require("qrcode");

const logger = bunyan.createLogger({
  name: "checkout-controller.js",
  level: process.env.LOG_LEVEL,
});

class MailController {
  static formatDateTime(value) {
    const formatter = new Intl.DateTimeFormat("de-DE", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: "Europe/Berlin",
    });
    return formatter.format(new Date(value));
  }

  static formatDate(value) {
    const formatter = new Intl.DateTimeFormat("de-DE", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
    });
    return formatter.format(new Date(value));
  }

  static formatCurrency(value) {
    const formatter = new Intl.NumberFormat("de-DE", {
      style: "currency",
      currency: "EUR",
    });
    return formatter.format(value);
  }

  static async getPopulatedBookables(bookingId, tenant) {
    let booking = await BookingManager.getBooking(bookingId, tenant);
    let bookables = (await BookableManager.getBookables(tenant)).filter((b) =>
      booking.bookableItems.some((bi) => bi.bookableId === b.id),
    );

    for (const bookable of bookables) {
      bookable._populated = {
        event: await EventManager.getEvent(bookable.eventId, bookable.tenantId),
      };
    }

    return bookables;
  }

  static async _sendBookingMail({
    address,
    bookingId,
    tenantId,
    subject,
    title,
    message,
    includeQRCode = false,
    attachments = [],
    sendBCC = false,
    addRejectionLink = false,
  }) {
    const tenant = await TenantManager.getTenant(tenantId);

    let bookingDetails = "";
    if (bookingId) {
      bookingDetails = await this.generateBookingDetails(bookingId, tenantId);
    }

    let content = `${message}<br>${bookingDetails}`;

    if (addRejectionLink) {
      content += `<br /><br /><a href="${process.env.FRONTEND_URL}/booking/request-reject/${tenantId}?id=${bookingId}">Buchung stornieren</a>`;
    }

    if (includeQRCode) {
      const { content: qrContent, attachment: qrAttachment } =
        await this.generateQRCode(bookingId, tenantId);
      content += `<br>${qrContent}`;
      attachments = attachments
        ? [...attachments, qrAttachment]
        : [qrAttachment];
    }

    const model = {
      title,
      content,
    };

    const bccEmail = sendBCC ? tenant.mail : undefined;

    await MailerService.send({
      tenantId: tenantId,
      address: address,
      subject: subject,
      mailTemplate: tenant.genericMailTemplate,
      model: model,
      attachments: attachments,
      bcc: bccEmail,
      useInstanceMail: tenant.useInstanceMail,
    });
  }

  static async generateBookingDetails(bookingId, tenantId) {
    let booking = await BookingManager.getBooking(bookingId, tenantId);
    let bookables = await MailController.getPopulatedBookables(
      bookingId,
      tenantId,
    );

    let content = `<strong>Buchungsnummer:</strong> ${booking.id}
            <br><strong>Gesamtbetrag:</strong> ${MailController.formatCurrency(
              booking.priceEur,
            )}             
            <br><strong>Firma:</strong> ${
              !booking.company ? "" : booking.company
            }
            <br><strong>Name:</strong> ${!booking.name ? "" : booking.name}
            <br><strong>Adresse:</strong> ${
              !booking.street ? "" : booking.street
            } in ${!booking.zipCode ? "" : booking.zipCode} ${
              !booking.location ? "" : booking.location
            }
            <br><strong>Telefon:</strong> ${!booking.phone ? "" : booking.phone}
            <br><strong>E-Mail:</strong> ${!booking.mail ? "" : booking.mail}
            <br><br><strong>Hinweise zur Buchung:</strong>
            <br>    ${!booking.comment ? "" : booking.comment}<br>`;

    if (booking.timeBegin && booking.timeEnd) {
      content += `<br><strong>Buchungszeitraum:</strong> ${MailController.formatDateTime(
        booking.timeBegin,
      )} - ${MailController.formatDateTime(booking.timeEnd)}`;
    }

    content += `<br>
            <h2>Bestellübersicht</h2>`;

    for (const bookableItem of booking.bookableItems) {
      const bookable = bookables.find((b) => b.id === bookableItem.bookableId);
      content += `<div style="border-bottom: solid 1px grey; margin-bottom: 10px; padding-bottom: 10px;">
                <strong>${bookable.title}, Anzahl: ${bookableItem.amount}</strong>`;

      if (
        bookable.type === "ticket" &&
        bookable.eventId &&
        bookable._populated?.event
      ) {
        content += `<div style="color: grey">
                    Ticket für die Veranstaltung ${
                      bookable._populated.event.information.name
                    }<br>
                    vom ${MailController.formatDate(
                      bookable._populated.event.information.startDate,
                    )} ${
                      bookable._populated.event.information.startTime
                    } bis ${MailController.formatDate(
                      bookable._populated.event.information.endDate,
                    )} ${bookable._populated.event.information.endTime}<br>
                    Ort: ${bookable._populated.event.eventLocation.name}, ${
                      bookable._populated.event.eventAddress.street
                    }, ${bookable._populated.event.eventAddress.houseNumber} ${
                      bookable._populated.event.eventAddress.zip
                    } ${bookable._populated.event.eventAddress.city}
                </div>`;
      }

      if (bookable.bookingNotes.length > 0) {
        content += `${bookable.bookingNotes}`;
      }

      content += `</div>`;
    }

    if (booking.coupon) {
      const coupon = booking.coupon;
      if (coupon.type === "fixed") {
        content += `<div style="color: grey">
                    Gutschein: ${coupon.description} (-${coupon.value}€)<br>
                </div>`;
      } else if (coupon.type === "percentage") {
        content += `<div style="color: grey">
                    Gutschein: ${coupon.description} (-${coupon.value}%)<br>
                </div>`;
      }
    }

    return content;
  }

  static async generateQRCode(bookingId, tenantId) {
    const booking = await BookingManager.getBooking(bookingId, tenantId);

    const AppUrl = process.env.FRONTEND_URL;

    const QRUrl = `${AppUrl}/booking/status/${tenantId}?id=${booking.id}&name=${encodeURIComponent(booking.name)}`;

    const qrCodeBuffer = await QRCode.toBuffer(QRUrl);

    const attachment = {
      filename: "qrcode.png",
      content: qrCodeBuffer,
      cid: "qrcode_cid",
    };

    const content = `
    <p>Mit diesem Link können Sie jederzeit den Status Ihrer Buchung einsehen.</p>
    <a href="${QRUrl}">${QRUrl}</a>
    <img src="cid:qrcode_cid" alt="QR Code" />`;

    return { content, attachment };
  }

  static async sendBookingConfirmation(
    address,
    bookingId,
    tenantId,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);
    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Vielen Dank für Ihre Buchung im ${tenant.name}`,
      title: `Vielen Dank für Ihre Buchung im ${tenant.name}`,
      message: `<p>Im Folgenden senden wir Ihnen die Details Ihrer Buchung.</p><br>`,
      includeQRCode: includeQRCode,
      attachments,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendBookingRejection(
    address,
    bookingId,
    tenantId,
    reason,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);

    let message = `<p>Die nachfolgende Buchung wurde abgelehnt:</p>`;
    if (reason) {
      reason = sanitizeReason(reason);
      message += `<p><strong>Ablehnungsgrund</strong>: ${reason}</p>`;
    }

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Abgelehnt: Ihre Buchungsanfrage im ${tenant.name} wurde abgelehnt`,
      title: `Ihre Buchungsanfrage im ${tenant.name} wurde abgelehnt`,
      message: message,
      includeQRCode: false,
      attachments,
      sendBCC: true,
      addRejectionLink: false,
    });
  }

  static async sendBookingCancel(
    address,
    bookingId,
    tenantId,
    reason,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);

    let message = `<p>Die nachfolgende Buchung wurde storniert:</p>`;
    if (reason) {
      reason = sanitizeReason(reason);
      message += `<p><strong>Hinweis zur Stornierung</strong>: ${reason}</p>`;
    }

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Stornierung: Ihre Buchung im ${tenant.name} wurde storniert`,
      title: `Ihre Buchung im ${tenant.name} wurde storniert`,
      message: message,
      includeQRCode: false,
      attachments,
      sendBCC: false,
      addRejectionLink: false,
    });
  }

  static async sendVerifyBookingRejection(
    address,
    bookingId,
    tenantId,
    hookId,
    reason,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);

    let message = `<p>Für die nachfolgende Buchung wurde eine Stornierung vorgemerkt. Wenn Sie diese Stornierung bestätigen möchten, klicken Sie bitte auf den nachfolgenden Link.</p><p>Sollten Sie die Stornierung nicht veranlasst haben, können Sie diese Nachricht ignorieren.</p>`;

    if (reason) {
      reason = sanitizeReason(reason);
      message += `<p><strong>Hinweis zur Stornierung</strong>: ${reason}</p>`;
    }

    message += `<p><a href="${process.env.FRONTEND_URL}/booking/verify-reject/${tenantId}?id=${bookingId}&hookId=${hookId}">Stornierung bestätigen</a></p>`;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Stornierungsanfrage für Ihre Buchung im ${tenant.name}`,
      title: `Stornierungsanfrage für Ihre Buchung im ${tenant.name}`,
      message: message,
      includeQRCode: false,
      attachments,
      sendBCC: false,
      addRejectionLink: false,
    });
  }

  static async sendFreeBookingConfirmation(address, bookingId, tenantId) {
    const tenant = await TenantManager.getTenant(tenantId);
    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Vielen Dank für Ihre Buchung im ${tenant.name}`,
      title: `Vielen Dank für Ihre Buchung im ${tenant.name}`,
      message: `<p>Im Folgenden senden wir Ihnen die Details Ihrer Buchung.</p><br>`,
      includeQRCode: includeQRCode,
      attachments: undefined,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendBookingRequestConfirmation(address, bookingId, tenantId) {
    const tenant = await TenantManager.getTenant(tenantId);

    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address: address,
      bookingId: bookingId,
      tenantId: tenantId,
      subject: `Vielen Dank für Ihre Buchungsanfrage im ${tenant.name}`,
      title: `Vielen Dank für Ihre Buchungsanfrage im ${tenant.name}`,
      message: `<p>Vielen Dank für Ihre Buchungsanfrage im ${tenant.name}. Wir haben Ihre Anfrage erhalten und bearbeiten diese schnellstmöglich.</p><br>`,
      includeQRCode: includeQRCode,
      attachments: undefined,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendInvoice(
    address,
    bookingId,
    tenantId,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);
    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Rechnung zu Ihrer Buchung bei ${tenant.name}`,
      title: `Rechnung zu Ihrer Buchung bei ${tenant.name}`,
      message: `<p>Vielen Dank für Ihre Buchung bei ${tenant.name}. Bitte überweisen Sie zur Vervollständigung Ihrer Buchung den im Anhang aufgeführten Betrag auf das angegebene Konto.</p><br>`,
      includeQRCode: includeQRCode,
      attachments,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendPaymentLinkAfterBookingApproval(
    address,
    bookingId,
    tenantId,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);
    const paymentLink = `${process.env.FRONTEND_URL}/payment/redirection?id=${bookingId}&tenant=${tenantId}`;
    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Bitte schließen Sie Ihre Buchung im ${tenant.name} ab`,
      title: `Bitte schließen Sie Ihre Buchung im ${tenant.name} ab`,
      message: `<p>Vielen Dank für Ihre Buchungsanfrage im ${tenant.name}. Wir haben diese erfolgreich geprüft und freigegeben. Bitte nutzen Sie den folgenden Link, um Ihre Buchung abzuschließen.</p><br><p><a href="${paymentLink}">${paymentLink}</a></p>`,
      includeQRCode: includeQRCode,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendInvoiceAfterBookingApproval(
    address,
    bookingId,
    tenantId,
    attachments = undefined,
  ) {
    const tenant = await TenantManager.getTenant(tenantId);
    const includeQRCode = tenant.enablePublicStatusView;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Bitte schließen Sie Ihre Buchung im ${tenant.name} ab`,
      title: `Bitte schließen Sie Ihre Buchung im ${tenant.name} ab`,
      message: `<p>Vielen Dank für Ihre Buchungsanfrage im ${tenant.name}. Wir haben diese erfolgreich geprüft und freigegeben. Bitte überweisen Sie zur Vervollständigung Ihrer Buchung den im Anhang aufgeführten Betrag auf das angegebene Konto.</p><br>`,
      includeQRCode: includeQRCode,
      attachments,
      sendBCC: false,
      addRejectionLink: true,
    });
  }

  static async sendPaymentRequest(
    address,
    bookingId,
    tenantId,
    attachments = undefined,
  ) {
    try {
      const booking = await BookingManager.getBooking(bookingId, tenantId);

      if (!booking) {
        throw new Error("Booking not found");
      }

      const paymentService = await PaymentUtils.getPaymentService(
        tenantId,
        bookingId,
        booking.paymentProvider,
        attachments,
      );

      if (!paymentService) return;

      await paymentService.paymentRequest();
    } catch (error) {
      logger.error(error);
      throw error;
    }
  }

  static async sendIncomingBooking(address, bookingId, tenantId) {
    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: `Eine neue Buchungsanfrage liegt vor`,
      title: `Eine neue Buchungsanfrage liegt vor`,
      message: `<p>Es liegt eine neue Buchungsanfrage vor.</p><br>`,
      sendBCC: false,
      addRejectionLink: false,
    });
  }

  static async sendNewBooking(address, bookingId, tenantId) {
    const message = `<p>Es liegt eine neue Buchung vor.</p><br>`;

    await this._sendBookingMail({
      address,
      bookingId,
      tenantId,
      subject: "Eine neue Buchung liegt vor",
      title: "Eine neue Buchung liegt vor",
      message,
      sendBCC: false,
    });
  }

  static async sendVerificationRequest(address, hookId) {
    let content = `<p>Um Ihre E-Mail-Adresse zu bestätigen, klicken Sie bitte auf den nachfolgenden Link</p><a href="${process.env.BACKEND_URL}/auth/verify/${hookId}">${process.env.BACKEND_URL}/auth/verify/${hookId}</a>`;
    const instance = await InstanceManager.getInstance(false);

    await MailerService.send({
      address,
      subject: "Bestätigen Sie Ihre E-Mail-Adresse",
      mailTemplate: instance.mailTemplate,
      model: {
        title: "Bestätigen Sie Ihre E-Mail-Adresse",
        content: content,
      },
    });
  }

  static async sendPasswordResetRequest(address, hookId) {
    let content = `<p>Ihr Kennwort wurde geändert. Um die Änderung zu bestätigen, klicken Sie bitte auf den nachfolgenden Link.<br>Falls Sie keine Änderung an Ihrem Kennwort vorgenommen haben, können Sie diese Nachricht ignorieren.</p><a href="${process.env.BACKEND_URL}/auth/reset/${hookId}">${process.env.BACKEND_URL}/auth/reset/${hookId}</a>`;
    const instance = await InstanceManager.getInstance(false);

    await MailerService.send({
      address,
      subject: "Bestätigen Sie die Änderung Ihres Kennworts",
      mailTemplate: instance.mailTemplate,
      model: {
        title: "Bestätigen Sie die Änderung Ihres Kennworts",
        content: content,
      },
    });
  }

  static async sendUserCreated(userId) {
    const instance = await InstanceManager.getInstance(false);

    const user = await UserManager.getUser(userId);

    let content = `<p>Ein neuer Benutzer wurde erstellt.</p><br>`;
    content += `<p>Vorname: ${user.firstName}</p>`;
    content += `<p>Nachname: ${user.lastName}</p>`;
    content += `<p>Firma: ${user.company}</p>`;
    content += `<p>E-Mail: ${user.id}</p>`;
    content += `<br>`;
    content += `<p> Registrierungsdatum: ${MailController.formatDateTime(user.created)}</p>`;

    await MailerService.send({
      address: instance.mailAddress,
      subject: "Ein neuer Benutzer wurde erstellt",
      mailTemplate: instance.mailTemplate,
      model: {
        title: "Ein neuer Benutzer wurde erstellt",
        content: content,
      },
    });
  }

  static async sendWorkflowNotification({
    sendTo,
    tenantId,
    bookingId,
    oldStatus,
    newStatus,
  }) {
    const tenant = await TenantManager.getTenant(tenantId);

    let content = `<p>Guten Tag</p><br>`;
    content += `<p>bitte beachten Sie, dass sich der Status der folgenden Buchung geändert hat:</p>`;
    content += `<ul>`;
    content += `<li><strong>Buchungsnummer:</strong> ${bookingId}</li>`;
    content += `<li><strong>Mandant:</strong> ${tenant.name}</li>`;
    content += `<li><strong>Alter Status:</strong> ${oldStatus}</li>`;
    content += `<li><strong>Neuer Status:</strong> ${newStatus}</li>`;
    content += `</ul>`;
    content += `<p>Aufgrund dieser Änderung ist ggf. eine Prüfung oder weitere Bearbeitung erforderlich.</p>`;

    await MailerService.send({
      address: sendTo,
      subject: `Änderung bei der Buchung Nr. ${bookingId} - Neuer Status`,
      mailTemplate: tenant.genericMailTemplate,
      model: {
        title: `Änderung bei der Buchung Nr. ${bookingId} - Neuer Status`,
        content: content,
      },
      useInstanceMail: tenant.useInstanceMail,
    });
  }
}

function sanitizeReason(reason) {
  if (typeof reason === "string" && reason.trim() !== "") {
    return reason.replace(/<[^>]*>?/gm, "");
  }
  return reason;
}

module.exports = MailController;
