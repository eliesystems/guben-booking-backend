const EventManager = require("../../../commons/data-managers/event-manager");
const { Event } = require("../../../commons/entities/event");
const { RolePermission } = require("../../../commons/entities/role");
const bunyan = require("bunyan");
const EventService = require("../../../commons/services/event-service");
const PermissionService = require("../../../commons/services/permission-service");

const logger = bunyan.createLogger({
  name: "event-controller.js",
  level: process.env.LOG_LEVEL,
});

/**
 * Web Controller for Events.
 */
class EventController {
  static async getEvents(request, response) {
    try {
      const tenant = request.params.tenant;
      const user = request.user;
      const events = await EventManager.getEvents(tenant);

      //TODO: Add Public version of events

      logger.info(
        `${tenant} -- sending ${events.length} events to user ${user?.id}`,
      );
      response.status(200).send(events);
    } catch (err) {
      logger.warn(err);
      response.status(500).send("could not get events");
    }
  }

  static async getEvent(request, response) {
    try {
      const tenant = request.params.tenant;
      const id = request.params.id;
      if (id) {
        const event = await EventManager.getEvent(id, tenant);

        //TODO: Add Public version of event

        response.status(200).send(event);
      } else {
        logger.warn(`Could not get event. Missing ID.`);
        response.sendStatus(400);
      }
    } catch (err) {
      logger.warn(err);
      response.status(500).send("could not get event");
    }
  }

  /**
   * @obsolute Use createEvent and updateEvent instead.
   * @param request
   * @param response
   * @returns {Promise<void>}
   */
  static async storeEvent(request, response) {
    const event = new Event(request.body);

    const isUpdate = !!event.id;

    if (isUpdate) {
      await EventController.updateEvent(request, response);
    } else {
      await EventController.createEvent(request, response);
    }
  }

  static async createEvent(request, response) {
    try {
      const {
        params: { tenant },
        user,
        body: event,
        query: { withTickets = "false" },
      } = request;

      const withTicketsBoolean = withTickets === "true";

      if (
        (await EventManager.checkPublicEventCount(tenant)) === false &&
        event.isPublic
      ) {
        throw new Error(`Maximum number of  public  events reached.`);
      }

      if (
        await PermissionService._allowCreate(
          event,
          user.id,
          tenant,
          RolePermission.MANAGE_BOOKABLES,
        )
      ) {
        await EventService.createEvent(tenant, event, user, withTicketsBoolean);

        logger.info(
          `${tenant} -- created event ${event.id} by user ${user?.id}`,
        );
        response.sendStatus(201);
      } else {
        logger.warn(`User ${user?.id} not allowed to create event`);
        response.sendStatus(403);
      }
    } catch (err) {
      logger.error(err);
      response.status(500).send("could not create event");
    }
  }

  static async updateEvent(request, response) {
    try {
      const tenant = request.params.tenant;
      const user = request.user;
      const event = new Event(request.body);

      const existingEvents = await EventManager.getEvent(event.id, tenant);

      if (!existingEvents?.isPublic && event.isPublic) {
        if ((await EventManager.checkPublicEventCount(tenant)) === false) {
          throw new Error(`Maximum number of public events reached.`);
        }
      }

      if (
        await PermissionService._allowUpdate(
          event,
          user.id,
          tenant,
          RolePermission.MANAGE_BOOKABLES,
        )
      ) {
        await EventManager.storeEvent(event);
        logger.info(
          `${tenant} -- updated event ${event.id} by user ${user?.id}`,
        );
        response.sendStatus(201);
      } else {
        logger.warn(`User ${user?.id} not allowed to update event`);
        response.sendStatus(403);
      }
    } catch (err) {
      logger.error(err);
      response.status(500).send("could not update event");
    }
  }

  static async removeEvent(request, response) {
    try {
      const tenant = request.params.tenant;
      const user = request.user;

      const id = request.params.id;
      if (id) {
        const event = await EventManager.getEvent(id, tenant);

        if (
          await PermissionService._allowDelete(
            event,
            user.id,
            tenant,
            RolePermission.MANAGE_BOOKABLES,
          )
        ) {
          await EventManager.removeEvent(id, tenant);
          logger.info(`${tenant} -- removed event ${id} by user ${user?.id}`);
          response.sendStatus(200);
        } else {
          logger.warn(`User ${user?.id} not allowed to remove event`);
          response.sendStatus(403);
        }
      } else {
        response.sendStatus(400);
      }
    } catch (err) {
      logger.error(err);
      response.status(500).send("could not remove event");
    }
  }

  static async getTags(request, response) {
    try {
      const tenant = request.params.tenant;
      const user = request.user;

      const events = await EventManager.getEvents(tenant);
      const tags = events
        .map((e) => e.information?.tags || [])
        .flat()
        .filter((value, index, self) => self.indexOf(value) === index);

      logger.info(
        `${tenant} -- sending ${tags.length} tags to user ${user?.id}`,
      );
      response.status(200).send(tags);
    } catch (err) {
      logger.error(err);
      response.status(500).send("could not get tags");
    }
  }
  static async countCheck(request, response) {
    try {
      const tenant = request.params.tenant;
      const isCreateAllowed = await EventManager.checkPublicEventCount(tenant);
      response.status(200).send(isCreateAllowed);
    } catch (err) {
      logger.error(err);
      response.status(500).send("Could not check if creation is possible");
    }
  }
}

module.exports = EventController;
