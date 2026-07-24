const request = require("supertest");
const app = require("../app");

describe("GET /", () => {
    it("should return response from server", async () => {
        const res = await request(app).get("/");

        expect(res.statusCode).toBe(200);
        expect(res.text).toBe("response from server");
    });
});