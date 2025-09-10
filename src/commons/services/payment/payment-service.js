const { getBooking } = require("../../data-managers/booking-manager");
const { getTenantApp } = require("../../data-managers/tenant-manager");
const jwkToPem = require("jwk-to-pem");
const bunyan = require("bunyan");
const axios = require("axios");
const qs = require("qs");
const crypto = require("crypto");
const BookingManager = require("../../data-managers/booking-manager");
const ReceiptService = require("./receipt-service");
const InvoiceService = require("./invoice-service");
const MailController = require("../../mail-service/mail-controller");
const Tenant = require("../../entities/tenant/tenant");

const logger = bunyan.createLogger({
  name: "payment-service.js",
  level: process.env.LOG_LEVEL,
});

class PaymentService {
  /**
   * @param {string} tenantId   - ID des Mandanten.
   * @param {string|string[]} bookingIds - Entweder eine einzelne Booking-ID oder ein Array von Booking-IDs.
   * @param {object} [options]  - Zusätzliche Optionen, z.B. { aggregated: true }
   */
  constructor(tenantId, bookingIds, options = {}) {
    this.tenantId = tenantId;
    this.bookingIds = Array.isArray(bookingIds) ? bookingIds : [bookingIds];
    this.aggregated = !!options.aggregated;
  }

  createPayment() {
    throw new Error("createPayment not implemented");
  }

  createSeparateInvoices() {
    throw new Error("createSeparateInvoices not implemented");
  }

  createAggregatedInvoice() {
    throw new Error("createAggregatedInvoice not implemented");
  }

  paymentNotification() {
    throw new Error("paymentNotification not implemented");
  }

  paymentResponse() {
    return `${process.env.FRONTEND_URL}/checkout/status?ids=${this.bookingIds.join(",")}&tenant=${this.tenantId}`;
  }

  paymentRequest() {
    throw new Error("paymentRequest not implemented");
  }

  async handleSuccessfulPayment({ bookingIds, tenantId, paymentMethod }) {
    const bookings = await BookingManager.getBookings(tenantId, bookingIds);
    const processedBookings = [];
    for (const booking of bookings) {
      booking.isPayed = true;
      booking.paymentMethod = paymentMethod;
      await BookingManager.setBookingPayedStatus(booking);
    }

    if (this.aggregated) {
      if (bookings.every((b) => b.isCommitted && b.isPayed)) {
        let attachments = [];
        if (bookings.reduce((acc, b) => acc + b.priceEur, 0) > 0) {
          const { receipt, name, receiptId, revision, timeCreated } =
            await ReceiptService.createAggregatedReceipt(
              tenantId,
              bookings.map((b) => b.id),
            );

          for (const booking of bookings) {
            booking.attachments.push({
              type: "receipt",
              title: name,
              receiptId: receiptId,
              revision: revision,
              timeCreated,
            });
            await BookingManager.storeBooking(booking);
          }

          attachments = [
            {
              filename: name,
              content: receipt.buffer,
              contentType: "application/pdf",
            },
          ];
        }

        try {
          await MailController.sendBookingConfirmation(
            bookings[0].mail,
            bookings.map((b) => b.id),
            tenantId,
            attachments,
            true,
          );
        } catch (err) {
          logger.error(err);
        }
      }

      return bookings;
    } else {
      for (const booking of bookings) {
        if (booking.isCommitted && booking.isPayed) {
          let attachments = [];
          if (booking.priceEur > 0) {
            const { receipt, name, receiptId, revision, timeCreated } =
              await ReceiptService.createSingleReceipt(tenantId, booking.id);

            booking.attachments.push({
              type: "receipt",
              title: name,
              receiptId: receiptId,
              revision: revision,
              timeCreated,
            });

            await BookingManager.storeBooking(booking);

            attachments = [
              {
                filename: name,
                content: receipt.buffer,
                contentType: "application/pdf",
              },
            ];
          }

          try {
            await MailController.sendBookingConfirmation(
              booking.mail,
              booking.id,
              tenantId,
              attachments,
            );
          } catch (err) {
            logger.error(err);
          }
        }
        processedBookings.push(booking);
      }
    }

    return processedBookings;
  }
}

class EPayBLPaymentService extends PaymentService {
  static EPAYBL_SUCCESS_CODE = "PAYED";
  static OAUTH_SERVER_URL = process.env.OAUTH_SERVER_URL;
  static PAYMENT_API_BASE_URL = process.env.PAYMENT_API_BASE_URL;
  static EPAYBL_PUBLIC_KEY = process.env.EPAYBL_PUBLIC_KEY;
  static EPAYBL_PRIVATE_KEY = process.env.EPAYBL_PRIVATE_KEY;

  constructor(tenantId, bookingIds, options = {}) {
    super(tenantId, bookingIds, options);
    this.clientId = null;
    this.privateKey = null;
    this.publicKey = null;
    this.cachedAccessToken = null;
    this.tokenExpiry = null;
  }

  async initializeKeys(paymentApp) {
    this.clientId = paymentApp.paymentMerchantId;
    this.privateKey = EPayBLPaymentService.EPAYBL_PRIVATE_KEY;
    this.publicKey = EPayBLPaymentService.EPAYBL_PUBLIC_KEY;
    this.cachedAccessToken = paymentApp.cachedAccessToken;
    this.tokenExpiry = paymentApp.tokenExpiry;
    
    if (!this.privateKey || !this.publicKey) {
      throw new Error("ePayBL: Private and public keys must be configured");
    }
  }

  createDPoPProofJWT(httpMethod, httpUri, accessToken = null) {
    const now = Math.floor(Date.now() / 1000);
    const publicKeyObj = JSON.parse(this.publicKey);
    
    const header = {
      typ: "dpop+jwt",
      alg: "RS256",
      jwk: publicKeyObj
    };

    const payload = {
      jti: uuidv4(),
      htm: httpMethod,
      htu: httpUri,
      iat: now
    };

    if (accessToken) {
      const tokenHash = crypto.createHash('sha256').update(accessToken).digest('base64url');
      payload.ath = tokenHash;
    }

    const privateKeyObj = JSON.parse(this.privateKey);
    
    const privateKeyPEM = jwkToPem(privateKeyObj, { private: true });
    
    return jwt.sign(payload, privateKeyPEM, {
      algorithm: 'RS256',
      header: header,
      noTimestamp: true
    });
  }

  createBearerToken() {
    const now = Math.floor(Date.now() / 1000);
    const publicKeyObj = JSON.parse(this.publicKey);
    
    const header = {
      alg: "RS256",
      kid: publicKeyObj.kid
    };

    const payload = {
      iss: this.clientId,
      sub: this.clientId,
      aud: EPayBLPaymentService.OAUTH_SERVER_URL,
      exp: now + 60,
      jti: uuidv4()
    };

    const privateKeyObj = JSON.parse(this.privateKey);
    const privateKeyPEM = jwkToPem(privateKeyObj, { private: true });

    return jwt.sign(payload, privateKeyPEM, {
      algorithm: 'RS256',
      header: header,
      noTimestamp: true
    });
  }

  async getAccessToken(paymentApp) {
    if (this.cachedAccessToken && this.tokenExpiry && Math.floor(Date.now() / 1000) < this.tokenExpiry) {
      return this.cachedAccessToken;
    }

    await this.initializeKeys(paymentApp);
    
    const tokenEndpoint = `${EPayBLPaymentService.OAUTH_SERVER_URL}/token`;
    
    // Create DPoP proof for token request
    const dpopProof = this.createDPoPProofJWT("POST", tokenEndpoint);
    
    // Create Bearer token for authentication
    const bearerToken = this.createBearerToken();
    
    const requestBody = qs.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: bearerToken
    });

    const config = {
      method: "post",
      url: tokenEndpoint,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "DPoP": dpopProof
      },
      data: requestBody,
    };

    try {
      const response = await axios(config);
      
      if (response.data?.access_token && response.data?.token_type === "DPoP") {
        //removing a few seconds for buffer here
        this.tokenExpiry = Math.floor(Date.now() / 1000) + response.data?.expires_in - 5;
        this.cachedAccessToken = response.data?.access_token;
        
        await Tenant.updatePaymentApplication(this.tenantId, this.cachedAccessToken, this.tokenExpiry);

        return response.data.access_token;
      } else {
        throw new Error(`Invalid token response: ${JSON.stringify(response.data)}`);
      }
    } catch (error) {
      logger.error(`ePayBL token request failed:`, error.response?.data || error.message);
      throw new Error(`ePayBL authentication failed: ${error.response?.data?.error_description || error.message}`);
    }
  }

  async createPayment() {
    if (this.aggregated) {
      return this.aggregatedPaymentUrl();
    } else {
      return this.createSeparatePaymentUrl();
    }
  }

  async createSeparatePaymentUrl() {
    const paymentUrls = [];
    
    for (const bookingId of this.bookingIds) {
      const booking = await getBooking(bookingId, this.tenantId);
      const paymentApp = await getTenantApp(this.tenantId, "ePayBL");
      
      // Get DPoP-bound access token
      const accessToken = await this.getAccessToken(paymentApp);
      
      const originatorId = paymentApp.paymentMerchantId;
      const endPointId = paymentApp.paymentProjectId;
      const apiUrl = `${EPayBLPaymentService.PAYMENT_API_BASE_URL}/paymenttransaction/${originatorId}/${endPointId}`;
      
      const requestId = booking.id;
      const amount = (booking.priceEur || 0);
      const purpose = `${booking.id} - ${paymentApp.paymentPurposeSuffix || ""}`.substring(0, 27);
      
      const redirectUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/responseV2?ids=${requestId}&tenant=${this.tenantId}&paymentMethod=${paymentApp.id}&aggregated=false`;
      
      const paymentRequest = {
        requestId: requestId,
        requestTimestamp: new Date().toISOString(),
        currency: "EUR",
        grossAmount: amount,
        purpose: this.sanitizePurpose(purpose),
        description: purpose,
        redirectUrl: redirectUrl,
        items: [
          {
            id: "01",
            reference: booking.bookableItems[0].bookableId,
            taxRate: booking.bookableItems[0]._bookableUsed.priceValueAddedTax,
            quantity: booking.bookableItems[0].amount,
            totalNetAmount: booking.bookableItems[0].userPriceEur * booking.bookableItems[0].amount,
            totalTaxAmount: (booking.bookableItems[0].userGrossPriceEur - booking.bookableItems[0].userPriceEur) * booking.bookableItems[0].amount,
            singleNetAmount: booking.bookableItems[0].userPriceEur,
            singleTaxAmount: booking.bookableItems[0].userGrossPriceEur - booking.bookableItems[0].userPriceEur,
          },
        ],
        requestor: {
          name: this.getLastName(booking.name),
          firstName: this.getFirstName(booking.name),
          isOrganization: booking.company ? true : false,
          ...(booking.company && { organizationName: booking.company }),
          address: {
            street: this.getStreetName(booking.street) || "",
            houseNumber: this.getHouseNumber(booking.street) || "",
            postalCode: booking.zipCode || "",
            city: booking.location || "",
          }
        }
      };

      // Create DPoP proof for this API call
      const dpopProof = this.createDPoPProofJWT("POST", apiUrl, accessToken);

      const config = {
        method: "post",
        url: apiUrl,
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Authorization": `DPoP ${accessToken}`,
          "DPoP": dpopProof
        },
        data: paymentRequest,
      };

      try {
        const response = await axios(config);

        if (response.data?.paymentInformation?.transactionUrl) {
          logger.info(`ePayBL Payment URL requested for booking ${requestId}: ${response.data.paymentInformation.transactionUrl}`);

          await BookingManager.updatePaymentTransactionId(booking.id, this.tenantId, response.data.paymentInformation.transactionId);

          paymentUrls.push({ 
            bookingId,
            url: response.data.paymentInformation.transactionUrl,
            transactionId: response.data.paymentInformation.transactionId
          });
        } else {
          logger.warn("ePayBL: could not get payment url.", response.data);
          throw new Error(`ePayBL: could not get payment url. Response: ${JSON.stringify(response.data)}`);
        }
      } catch (error) {
        logger.error(`ePayBL payment URL creation failed for booking ${requestId}:`, error.response?.data || error.message);
        throw new Error(`ePayBL payment creation failed: ${error.response?.data?.message || error.message}`);
      }
    }
    return paymentUrls;
  }

  async aggregatedPaymentUrl() {
    const bookings = await BookingManager.getBookings(
      this.tenantId,
      this.bookingIds,
    );
    const paymentApp = await getTenantApp(this.tenantId, "ePayBL");
    
    // Get DPoP-bound access token
    const accessToken = await this.getAccessToken(paymentApp);
    
    const originatorId = paymentApp.paymentMerchantId;
    const endPointId = paymentApp.paymentProjectId;
    const apiUrl = `${EPayBLPaymentService.PAYMENT_API_BASE_URL}/paymenttransaction/${originatorId}/${endPointId}`;
    
    const requestId = `${this.bookingIds.join(",")}`;
    const amount = bookings.reduce((acc, booking) => {
      return acc + (booking.priceEur || 0);
    }, 0);
    const purpose = `${this.bookingIds.join(",")} - ${
      paymentApp.paymentPurposeSuffix || ""
    }`;

    const redirectUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/responseV2?ids=${requestId}&tenant=${this.tenantId}&paymentMethod=${paymentApp.id}&aggregated=true`;

    const items = bookings.map((booking, index) => ({
      id: String(index + 1).padStart(2, '0'),
      reference: booking.bookableItems[index].bookableId,
      taxRate: booking.bookableItems[index]._bookableUsed.priceValueAddedTax,
      quantity: booking.bookableItems[index].amount,
      totalNetAmount: booking.bookableItems[index].userPriceEur * booking.bookableItems[index].amount,
      totalTaxAmount: (booking.bookableItems[index].userGrossPriceEur - booking.bookableItems[index].userPriceEur) * booking.bookableItems[index].amount,
      singleNetAmount: booking.bookableItems[index].userPriceEur,
      singleTaxAmount: booking.bookableItems[index].userGrossPriceEur - booking.bookableItems[index].userPriceEur,
    }));

    const paymentRequest = {
      requestId: uuidv4(),
      requestTimestamp: new Date().toISOString(),
      currency: "EUR",
      grossAmount: amount,
      purpose: this.sanitizePurpose(purpose),
      description: this.sanitizeDescription(requestId),
      redirectUrl: redirectUrl,
      items: items,
      requestor: {
        name: this.getLastName(bookings[0]?.name) || "",
        firstName: this.getFirstName(bookings[0]?.name) || "",
        isOrganization: bookings[0]?.company ? true : false,
        ...(bookings[0]?.company && { organizationName: bookings[0]?.company }),
        address: {
          street: this.getStreetName(bookings[0]?.street) || "",
          houseNumber: this.getHouseNumber(bookings[0]?.street) || "",
          postalCode: bookings[0]?.zipCode || "",
          city: bookings[0]?.location || "",
        }
      }
    };

    // Create DPoP proof for this API call
    const dpopProof = this.createDPoPProofJWT("POST", apiUrl, accessToken);

    const config = {
      method: "post",
      url: apiUrl,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": `DPoP ${accessToken}`,
        "DPoP": dpopProof
      },
      data: paymentRequest,
    };

    try {
      const response = await axios(config);

      if (response.data?.paymentInformation?.transactionUrl) {
        logger.info(`ePayBL Payment URL requested for bookings ${requestId}: ${response.data.paymentInformation.transactionUrl}`);
        return [{ 
          bookingIds: this.bookingIds, 
          url: response.data.paymentInformation.transactionUrl,
          transactionId: response.data.paymentInformation.transactionId
        }];
      } else {
        logger.warn("ePayBL: could not get payment url.", response.data);
        throw new Error(`ePayBL: could not get payment url. Response: ${JSON.stringify(response.data)}`);
      }
    } catch (error) {
      logger.error(`ePayBL aggregated payment URL creation failed for bookings ${requestId}:`, error.response?.data || error.message);
      throw new Error(`ePayBL payment creation failed: ${error.response?.data?.message || error.message}`);
    }
  }

  getStreetName(streetWithNumber) {
    const match = streetWithNumber.match(/^(.+?)\s+\d+.*$/);
    return match ? match[1].trim() : streetWithNumber;
  }

  getHouseNumber(streetWithNumber) {
    const match = streetWithNumber.match(/\s+(\d+.*)$/);
    return match ? match[1].trim() : "";
  }

  getLastName(fullName) {
    const parts = fullName.trim().split(' ');
    return parts[parts.length - 1];
  }

  getFirstName(fullName) {
    const parts = fullName.trim().split(' ');
    return parts.slice(0, -1).join(' ');
  }

  sanitizePurpose(purpose) {
    if (!purpose) return "";

    purpose = purpose
      .replace(/ä/g, "ae")
      .replace(/ö/g, "oe")
      .replace(/ü/g, "ue")
      .replace(/Ä/g, "Ae")
      .replace(/Ö/g, "Oe")
      .replace(/Ü/g, "Ue")
      .replace(/ß/g, "ss");

    return purpose
      .replace(/[^\w\d\s-]/g, "")
      .substring(0, 27)
      .trim();
  }

  sanitizeDescription(description) {
    if (!description) return "";

    return description
      .substring(0, 250)
      .trim();
  }

  async getPaymentStatus(transactionId) {
    const paymentApp = await getTenantApp(this.tenantId, "ePayBL");
    const accessToken = await this.getAccessToken(paymentApp);
    
    const originatorId = paymentApp.paymentMerchantId;
    const endPointId = paymentApp.paymentProjectId;
    const statusUrl = `${EPayBLPaymentService.PAYMENT_API_BASE_URL}/paymenttransaction/${originatorId}/${endPointId}/${transactionId}`;
    
    // Create DPoP proof for GET request
    const dpopProof = this.createDPoPProofJWT("GET", statusUrl, accessToken);
    
    const config = {
      method: "get",
      url: statusUrl,
      headers: {
        "Authorization": `DPoP ${accessToken}`,
        "Accept": "application/json",
        "DPoP": dpopProof
      }
    };

    try {
      const response = await axios(config);

      const paymentInformation = response.data?.paymentInformation;
      const paymentMethod = paymentInformation.paymentMethod;
      const status = paymentInformation.status;

      if (status === EPayBLPaymentService.EPAYBL_SUCCESS_CODE) {
        logger.info(`${this.tenantId} -- ePayBL responds with status ${EPayBLPaymentService.EPAYBL_SUCCESS_CODE} / successfully paid for bookings ${this.bookingIds}.`);

        await this.handleSuccessfulPayment({
          bookingIds: this.bookingIds,
          tenantId: this.tenantId,
          paymentMethod: paymentMethod || "OTHER",
        });

        logger.info(`${this.tenantId} -- bookings ${this.bookingIds} successfully paid via ePayBL and updated.`);
      } else {
        logger.warn(`${this.tenantId} -- ePayBL payment failed for bookings ${this.bookingIds}. Status: ${status}`);
      }
    } catch (error) {
      logger.error(`ePayBL status check failed for transaction ${transactionId}:`, error.response?.data || error.message);
      throw error;
    }
  }
  
  async paymentRequest() {
    if (this.aggregated) {
      return this.aggregatedPaymentLink();
    } else {
      return this.separatePaymentLink();
    }
  }

  async separatePaymentLink() {
    try {
      for (const bookingId of this.bookingIds) {
        const booking = await BookingManager.getBooking(
          bookingId,
          this.tenantId
        );

        await MailController.sendPaymentLinkAfterBookingApproval(
          booking.mail,
          bookingId,
          this.tenantId,
        );
      }
    } catch (error) {
      logger.error(`EPayBL separate payment Link error`, error);
      throw error;
    }
  }

  async aggregatedPaymentLink() {
    try {
      const bookings = await BookingManager.getBookings(
        this.tenantId,
        this.bookingIds,
      );

      await MailController.sendPaymentLinkAfterBookingApproval(
        bookings[0].mail,
        this.bookingIds,
        this.tenantId,
        true,
      );
    } catch (error) {
      logger.error(`ePayBL aggregated payment link error:`, error);
      throw error;
    }
  }

  async handleSuccessfulPayment({ bookingIds, tenantId, paymentMethod }) {
    await super.handleSuccessfulPayment({
      bookingIds,
      tenantId,
      paymentMethod,
    });
  }
}

class GiroCockpitPaymentService extends PaymentService {
  static GIRO_SUCCESS_CODE = "4000";

  async createPayment() {
    if (this.aggregated) {
      return this.aggregatedPaymentUrl();
    } else {
      return this.createSeparatePaymentUrl();
    }
  }

  async createSeparatePaymentUrl() {
    const paymentUrls = [];
    for (const bookingId of this.bookingIds) {
      const booking = await getBooking(bookingId, this.tenantId);
      const paymentApp = await getTenantApp(this.tenantId, "giroCockpit");
      const GIRO_CHECKOUT_URL =
        "https://payment.girosolution.de/girocheckout/api/v2/paypage/init";
      const type = "SALE";
      const test = 1;
      const currency = "EUR";

      const merchantTxId = booking.id;
      const amount = (booking.priceEur * 100 || 0).toString();
      const purpose = `${booking.id} ${paymentApp.paymentPurposeSuffix || ""}`;

      const MERCHANT_ID = paymentApp.paymentMerchantId;
      const PROJECT_ID = paymentApp.paymentProjectId;
      const PROJECT_SECRET = paymentApp.paymentSecret;

      const notifyUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/notify?ids=${merchantTxId}&aggregated=false`;
      const successUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=success&paymentMethod=${paymentApp.id}&aggregated=false`;
      const failUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=fail&paymentMethod=${paymentApp.id}&aggregated=false`;
      const backUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=back&paymentMethod=${paymentApp.id}&aggregated=false`;
      const hash = crypto
        .createHmac("md5", PROJECT_SECRET)
        .update(
          `${MERCHANT_ID}${PROJECT_ID}${merchantTxId}${amount}${currency}${purpose}${type}${test}${successUrl}${backUrl}${failUrl}${notifyUrl}`,
        )
        .digest("hex");

      const data = qs.stringify({
        merchantId: MERCHANT_ID,
        projectId: PROJECT_ID,
        merchantTxId: merchantTxId,
        amount: amount,
        currency: currency,
        purpose: purpose,
        type: type,
        test: test,
        successUrl: successUrl,
        backUrl: backUrl,
        failUrl: failUrl,
        notifyUrl: notifyUrl,
        hash: hash,
      });

      const config = {
        method: "post",
        url: GIRO_CHECKOUT_URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: data,
      };

      const response = await axios(config);

      if (response.data?.url) {
        logger.info(
          `Payment URL requested for booking ${merchantTxId}: ${response.data?.url}`,
        );
        paymentUrls.push({ bookingId, url: response.data?.url });
      } else {
        logger.warn("could not get payment url.", response.data);
        throw new Error("could not get payment url.");
      }
    }
    return paymentUrls;
  }

  async aggregatedPaymentUrl() {
    const bookings = await BookingManager.getBookings(
      this.tenantId,
      this.bookingIds,
    );
    const paymentApp = await getTenantApp(this.tenantId, "giroCockpit");
    const GIRO_CHECKOUT_URL =
      "https://payment.girosolution.de/girocheckout/api/v2/paypage/init";
    const type = "SALE";
    const test = 1;
    const currency = "EUR";

    const merchantTxId = this.bookingIds.join(",");
    const amount = bookings.reduce((acc, booking) => {
      return acc + booking.priceEur * 100 || 0;
    }, 0);
    const purpose = `${this.bookingIds.join(",")} ${
      paymentApp.paymentPurposeSuffix || ""
    }`;

    const MERCHANT_ID = paymentApp.paymentMerchantId;
    const PROJECT_ID = paymentApp.paymentProjectId;
    const PROJECT_SECRET = paymentApp.paymentSecret;

    const notifyUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/notify?ids=${merchantTxId}&aggregated=true`;
    const successUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=success&paymentMethod=${paymentApp.id}&aggregated=true`;
    const failUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=fail&paymentMethod=${paymentApp.id}&aggregated=true`;
    const backUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${merchantTxId}&tenant=${this.tenantId}&status=back&paymentMethod=${paymentApp.id}&aggregated=true`;
    const hash = crypto
      .createHmac("md5", PROJECT_SECRET)
      .update(
        `${MERCHANT_ID}${PROJECT_ID}${merchantTxId}${amount}${currency}${purpose}${type}${test}${successUrl}${backUrl}${failUrl}${notifyUrl}`,
      )
      .digest("hex");

    const data = qs.stringify({
      merchantId: MERCHANT_ID,
      projectId: PROJECT_ID,
      merchantTxId: merchantTxId,
      amount: amount,
      currency: currency,
      purpose: purpose,
      type: type,
      test: test,
      successUrl: successUrl,
      backUrl: backUrl,
      failUrl: failUrl,
      notifyUrl: notifyUrl,
      hash: hash,
    });

    const config = {
      method: "post",
      url: GIRO_CHECKOUT_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: data,
    };

    const response = await axios(config);

    if (response.data?.url) {
      logger.info(
        `Payment URL requested for booking ${merchantTxId}: ${response.data?.url}`,
      );
      return [{ bookingIds: this.bookingIds, url: response.data?.url }];
    } else {
      logger.warn("could not get payment url.", response.data);
      throw new Error("could not get payment url.");
    }
  }

  async paymentNotification(query) {
    const {
      gcMerchantTxId,
      gcResultPayment,
      gcPaymethod,
      gcType,
      gcProjectId,
      gcReference,
      gcBackendTxId,
      gcAmount,
      gcCurrency,
      gcHash,
    } = query;

    try {
      if (!this.bookingIds || !this.tenantId) {
        logger.warn(
          `${this.tenantId} -- could not validate payment notification. Missing parameters. For Booking ${this.bookingId}`,
        );
        throw new Error("Missing parameters");
      }
      const paymentApp = await getTenantApp(this.tenantId, "giroCockpit");
      const PROJECT_SECRET = paymentApp.paymentSecret;

      const hashString =
        gcPaymethod +
        gcType +
        gcProjectId +
        gcReference +
        gcMerchantTxId +
        gcBackendTxId +
        gcAmount +
        gcCurrency +
        gcResultPayment;

      const hash = crypto
        .createHmac("md5", PROJECT_SECRET)
        .update(hashString)
        .digest("hex");

      if (gcHash !== hash) {
        logger.warn(
          `${this.tenantId} -- payment notification hash mismatch. For Bookings ${this.bookingIds}`,
        );
        throw new Error("Hash mismatch");
      }

      if (gcResultPayment === GiroCockpitPaymentService.GIRO_SUCCESS_CODE) {
        logger.info(
          `${this.tenantId} -- GiroCockpit responds with status ${GiroCockpitPaymentService.GIRO_SUCCESS_CODE} / successfully payed for bookings ${this.bookingIds} .`,
        );

        const paymentMapping = {
          1: "GIROPAY",
          17: "GIROPAY",
          18: "GIROPAY",
          2: "EPS",
          12: "IDEAL",
          11: "CREDIT_CARD",
          6: "TRANSFER",
          7: "TRANSFER",
          26: "BLUECODE",
          33: "MAESTRO",
          14: "PAYPAL",
          23: "PAYDIRECT",
          27: "SOFORT",
        };

        await this.handleSuccessfulPayment({
          bookingIds: this.bookingIds,
          tenantId: this.tenantId,
          paymentMethod: paymentMapping[gcPaymethod] || "OTHER",
        });

        logger.info(
          `${this.tenantId} -- bookings ${this.bookingIds} successfully payed and updated.`,
        );

        return true;
      } else {
        // TODO: remove booking?
        logger.warn(
          `${this.tenantId} -- bookings ${this.bookingIds} could not be payed.`,
        );
        return true;
      }
    } catch (error) {
      throw error;
    }
  }

  async paymentRequest() {
    if (this.aggregated) {
      return this.aggregatedPaymentLink();
    } else {
      return this.separatePaymentLink();
    }
  }

  async separatePaymentLink() {
    try {
      for (const bookingId of this.bookingIds) {
        const booking = await BookingManager.getBooking(
          bookingId,
          this.tenantId,
        );

        await MailController.sendPaymentLinkAfterBookingApproval(
          booking.mail,
          bookingId,
          this.tenantId,
        );
      }
    } catch (error) {
      throw error;
    }
  }

  async aggregatedPaymentLink() {
    const bookings = await BookingManager.getBookings(
      this.tenantId,
      this.bookingIds,
    );

    await MailController.sendPaymentLinkAfterBookingApproval(
      bookings[0].mail,
      this.bookingIds,
      this.tenantId,
      true,
    );
  }

  async handleSuccessfulPayment({ bookingIds, tenantId, paymentMethod }) {
    await super.handleSuccessfulPayment({
      bookingIds,
      tenantId,
      paymentMethod,
    });
  }
}

class PmPaymentService extends PaymentService {
  static PM_SUCCESS_CODE = 1;

  async createPayment() {
    if (this.aggregated) {
      return this.aggregatedPaymentUrl();
    } else {
      return this.createSeparatePaymentUrl();
    }
  }

  async createSeparatePaymentUrl() {
    const paymentUrls = [];
    for (const bookingId of this.bookingIds) {
      const booking = await getBooking(bookingId, this.tenantId);
      const paymentApp = await getTenantApp(this.tenantId, "pmPayment");
      let PM_CHECKOUT_URL;
      if (paymentApp.paymentMode === "prod") {
        PM_CHECKOUT_URL = "https://payment.govconnect.de/payment/secure";
      } else {
        PM_CHECKOUT_URL = "https://payment-test.govconnect.de/payment/secure";
      }

      const amount = (booking.priceEur * 100 || 0).toString();
      const desc = `${bookingId} ${paymentApp.paymentPurposeSuffix || ""}`;
      const AGS = paymentApp.paymentMerchantId;
      const PROCEDURE = paymentApp.paymentProjectId;
      const PAYMENT_SALT = paymentApp.paymentSecret;

      const notifyUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/notify?ids=${bookingId}`;
      const redirectUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${bookingId}&tenant=${this.tenantId}&paymentMethod=${paymentApp.id}`;

      const hash = crypto
        .createHmac("sha256", PAYMENT_SALT)
        .update(
          `${AGS}|${amount}|${PROCEDURE}|${desc}|${notifyUrl}|${redirectUrl}`,
        )
        .digest("hex");

      const data = qs.stringify({
        ags: AGS,
        amount: amount,
        procedure: PROCEDURE,
        desc: desc,
        notifyURL: notifyUrl,
        redirectURL: redirectUrl,
        hash: hash,
      });

      const config = {
        method: "post",
        url: PM_CHECKOUT_URL,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: data,
      };

      const response = await axios(config);

      if (response.data?.url) {
        logger.info(
          `Payment URL requested for booking ${bookingId}: ${response.data?.url}`,
        );
        paymentUrls.push({ bookingId, url: response.data?.url });
      } else {
        logger.warn("could not get payment url.", response.data);
        throw new Error("could not get payment url.");
      }
    }
    return paymentUrls;
  }

  async aggregatedPaymentUrl() {
    const bookings = await BookingManager.getBookings(
      this.tenantId,
      this.bookingIds,
    );

    const paymentApp = await getTenantApp(this.tenantId, "pmPayment");
    let PM_CHECKOUT_URL;
    if (paymentApp.paymentMode === "prod") {
      PM_CHECKOUT_URL = "https://payment.govconnect.de/payment/secure";
    } else {
      PM_CHECKOUT_URL = "https://payment-test.govconnect.de/payment/secure";
    }

    const amount = bookings.reduce((acc, booking) => {
      return acc + booking.priceEur * 100 || 0;
    }, 0);

    const desc = `${this.bookingIds.join(",")} ${
      paymentApp.paymentPurposeSuffix || ""
    }`;
    const AGS = paymentApp.paymentMerchantId;
    const PROCEDURE = paymentApp.paymentProjectId;
    const PAYMENT_SALT = paymentApp.paymentSecret;

    const notifyUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/notify?ids=${this.bookingIds.join(",")}&aggregated=true`;
    const redirectUrl = `${process.env.BACKEND_URL}/api/${this.tenantId}/payments/response?ids=${this.bookingIds.join(",")}&tenant=${this.tenantId}&paymentMethod=${paymentApp.id}&aggregated=true`;

    const hash = crypto
      .createHmac("sha256", PAYMENT_SALT)
      .update(
        `${AGS}|${amount}|${PROCEDURE}|${desc}|${notifyUrl}|${redirectUrl}`,
      )
      .digest("hex");

    const data = qs.stringify({
      ags: AGS,
      amount: amount,
      procedure: PROCEDURE,
      desc: desc,
      notifyURL: notifyUrl,
      redirectURL: redirectUrl,
      hash: hash,
    });

    const config = {
      method: "post",
      url: PM_CHECKOUT_URL,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: data,
    };

    const response = await axios(config);

    if (response.data?.url) {
      logger.info(
        `Payment URL requested for booking ${this.bookingIds}: ${response.data?.url}`,
      );
      return [{ bookingIds: this.bookingIds, url: response.data?.url }];
    } else {
      logger.warn("could not get payment url.", response.data);
      throw new Error("could not get payment url.");
    }
  }

  async paymentRequest() {
    if (this.aggregated) {
      return this.aggregatedPaymentLink();
    } else {
      return this.separatePaymentLink();
    }
  }

  async separatePaymentLink() {
    try {
      for (const bookingId of this.bookingIds) {
        const booking = await BookingManager.getBooking(
          bookingId,
          this.tenantId,
        );

        await MailController.sendPaymentLinkAfterBookingApproval(
          booking.mail,
          bookingId,
          this.tenantId,
        );
      }
    } catch (error) {
      throw error;
    }
  }

  async aggregatedPaymentLink() {
    const bookings = await BookingManager.getBookings(
      this.tenantId,
      this.bookingIds,
    );

    await MailController.sendPaymentLinkAfterBookingApproval(
      bookings[0].mail,
      this.bookingIds,
      this.tenantId,
      true,
    );
  }

  async paymentNotification(body) {
    const { ags, txid, payment_method: paymentProvider } = body;

    try {
      if (!this.bookingIds || !this.tenantId) {
        logger.warn(
          `${this.tenantId} -- could not validate payment notification. Missing parameters. For Bookings ${this.bookingIds}`,
        );
        throw new Error("Missing parameters");
      }

      const paymentApp = await getTenantApp(this.tenantId, "pmPayment");
      let PM_STATUS_URL;
      if (paymentApp.paymentProvider === "prod") {
        PM_STATUS_URL = "https://payment.govconnect.de/payment/status";
      } else {
        PM_STATUS_URL = "https://payment-test.govconnect.de/payment/status";
      }

      const config = {
        method: "get",
        url: `${PM_STATUS_URL}/${ags}/${txid}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      };

      const response = await axios(config);

      if (response.data.status === PmPaymentService.PM_SUCCESS_CODE) {
        logger.info(
          `${this.tenantId} -- pmPayment responds with status ${PmPaymentService.PM_SUCCESS_CODE} / successfully payed for bookings ${this.bookingIds} .`,
        );

        const paymentMapping = {
          giropay: "GIROPAY",
          sepa: "TRANSFER",
          creditCard: "CREDIT_CARD",
          paypal: "PAYPAL",
          applePay: "APPLE_PAY",
          googlePay: "GOOGLE_PAY",
        };

        await this.handleSuccessfulPayment({
          bookingIds: this.bookingIds,
          tenantId: this.tenantId,
          paymentMethod: paymentMapping[paymentProvider] || "OTHER",
        });

        logger.info(
          `${this.tenantId} -- bookings ${this.bookingIds} successfully payed and updated.`,
        );

        return true;
      } else {
        // TODO: remove booking?
        logger.warn(
          `${this.tenantId} -- bookings ${this.bookingIds} could not be payed.`,
        );
        return true;
      }
    } catch (error) {
      logger.error(
        `${this.tenantId} -- payment notification error. For Bookings ${this.bookingIds}`,
      );
      throw error;
    }
  }

  async handleSuccessfulPayment({ bookingIds, tenantId, paymentMethod }) {
    await super.handleSuccessfulPayment({
      bookingIds,
      tenantId,
      paymentMethod,
    });
  }
}

class InvoicePaymentService extends PaymentService {
  constructor(tenantId, bookingIds, options = {}) {
    super(tenantId, bookingIds, options);
  }
  async createPayment() {
    if (this.aggregated) {
      return this.createAggregatedInvoice();
    } else {
      return this.createSeparateInvoices();
    }
  }

  async createSeparateInvoices() {
    const createdInvoices = [];
    for (const bookingId of this.bookingIds) {
      const booking = await BookingManager.getBooking(bookingId, this.tenantId);

      const { invoice, name, invoiceId, revision, timeCreated } =
        await InvoiceService.createSingleInvoice(this.tenantId, bookingId);

      booking.attachments.push({
        type: "invoice",
        name,
        invoiceId,
        revision,
        timeCreated,
      });
      await BookingManager.storeBooking(booking);

      const attachments = [
        {
          filename: name,
          content: invoice.buffer,
          contentType: "application/pdf",
        },
      ];

      try {
        await MailController.sendInvoice(
          booking.mail,
          bookingId,
          this.tenantId,
          attachments,
        );
      } catch (err) {
        logger.error("Error while sending invoice:", bookingId, err);
      }

      createdInvoices.push({
        bookingId,
        name,
        invoiceId,
        revision,
      });
    }

    return createdInvoices;
  }

  async createAggregatedInvoice() {
    const bookings = [];
    for (const bookingId of this.bookingIds) {
      const booking = await BookingManager.getBooking(bookingId, this.tenantId);
      bookings.push(booking);
    }

    const { invoice, name, invoiceId, revision, timeCreated } =
      await InvoiceService.createAggregatedInvoice(this.tenantId, bookings);

    for (const booking of bookings) {
      booking.attachments.push({
        type: "invoice",
        name,
        invoiceId,
        revision,
        timeCreated,
        aggregated: true,
      });
      await BookingManager.storeBooking(booking);
    }

    const attachments = [
      {
        filename: name,
        content: invoice.buffer,
        contentType: "application/pdf",
      },
    ];

    try {
      await MailController.sendInvoice(
        bookings[0].mail,
        this.bookingIds,
        this.tenantId,
        attachments,
        true,
      );
    } catch (err) {
      logger.error("Fehler beim Versenden der Sammelrechnung:", err);
    }
  }

  async paymentNotification() {
    console.log("paymentNotification");
  }

  async paymentRequest() {
    if (this.aggregated) {
      return this.aggregatedPaymentRequest();
    } else {
      return this.separatePaymentRequest();
    }
  }

  async separatePaymentRequest() {
    try {
      for (const bookingId of this.bookingIds) {
        const booking = await BookingManager.getBooking(
          bookingId,
          this.tenantId,
        );

        const { invoice, name, invoiceId, revision, timeCreated } =
          await InvoiceService.createSingleInvoice(this.tenantId, bookingId);

        booking.attachments.push({
          type: "invoice",
          name,
          invoiceId,
          revision,
          timeCreated,
        });
        await BookingManager.storeBooking(booking);

        const attachments = [
          {
            filename: name,
            content: invoice.buffer,
            contentType: "application/pdf",
          },
        ];
        await MailController.sendInvoiceAfterBookingApproval(
          booking.mail,
          bookingId,
          this.tenantId,
          attachments,
          false,
        );
      }
    } catch (error) {
      throw error;
    }
  }

  async aggregatedPaymentRequest() {
    const bookings = [];
    for (const bookingId of this.bookingIds) {
      const booking = await BookingManager.getBooking(bookingId, this.tenantId);
      bookings.push(booking);
    }

    const { invoice, name, invoiceId, revision, timeCreated } =
      await InvoiceService.createAggregatedInvoice(
        this.tenantId,
        this.bookingIds,
      );

    for (const booking of bookings) {
      booking.attachments.push({
        type: "invoice",
        name,
        invoiceId,
        revision,
        timeCreated,
      });
      await BookingManager.storeBooking(booking);
    }

    const attachments = [
      {
        filename: name,
        content: invoice.buffer,
        contentType: "application/pdf",
      },
    ];
    await MailController.sendInvoiceAfterBookingApproval(
      bookings[0].mail,
      bookings.map((b) => b.id),
      this.tenantId,
      attachments,
      true,
    );
  }
}

module.exports = {
  EPayBLPaymentService,
  GiroCockpitPaymentService,
  PmPaymentService,
  InvoicePaymentService,
};
