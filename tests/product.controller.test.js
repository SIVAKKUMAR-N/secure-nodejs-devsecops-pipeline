const product = require("../models/product.model");
const { getproducts } = require("../controllers/product.controller");

jest.mock("../models/product.model");

describe("getproducts", () => {
    it("should return all products", async () => {

        const req = {};

        const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        };

        const fakeProducts = [
            {
                name: "Laptop",
                price: 50000
            }
        ];

        product.find.mockResolvedValue(fakeProducts);

        await getproducts(req, res);

        expect(product.find).toHaveBeenCalled();

        expect(res.status).toHaveBeenCalledWith(200);

        expect(res.json).toHaveBeenCalledWith(fakeProducts);
    });
});