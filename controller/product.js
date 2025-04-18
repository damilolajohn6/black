require("dotenv").config();
const express = require("express");
const { isSeller, isAuthenticated, isAdmin } = require("../middleware/auth");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const router = express.Router();
const Product = require("../model/product");
const Order = require("../model/order");
const Shop = require("../model/shop");
const ErrorHandler = require("../utils/ErrorHandler");

// Create product
router.post(
  "/create-product",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      if (!req.seller || !req.seller._id) {
        console.error("create-product: Seller not authenticated", {
          cookies: req.cookies,
          headers: req.headers.authorization,
        });
        return next(new ErrorHandler("Seller not authenticated", 401));
      }

      const shopId = req.body.shopId;
      if (!shopId) {
        return next(new ErrorHandler("Shop ID is required", 400));
      }

      const shop = await Shop.findById(shopId);
      if (!shop) {
        return next(new ErrorHandler("Invalid Shop ID", 400));
      }

      if (shop._id.toString() !== req.seller._id.toString()) {
        return next(
          new ErrorHandler("Unauthorized: Shop does not belong to seller", 403)
        );
      }

      const {
        name,
        description,
        category,
        price,
        stock,
        images,
        priceDiscount,
        subCategory,
        tags,
        shipping,
        variations,
        isMadeInCanada,
        canadianCertification,
      } = req.body;

      if (!name || !description || !category || !price || stock === undefined) {
        return next(
          new ErrorHandler(
            "Missing required fields: name, description, category, price, stock",
            400
          )
        );
      }

      if (!Array.isArray(images) || images.length === 0) {
        return next(new ErrorHandler("At least one image is required", 400));
      }

      const imagesLinks = images.map((image) => ({
        public_id: image.public_id || "",
        url: image.url,
      }));

      for (const image of imagesLinks) {
        if (!image.url) {
          return next(
            new ErrorHandler("Each image must have a valid URL", 400)
          );
        }
      }

      const productData = {
        name,
        description,
        category,
        price: Number(price),
        stock: Number(stock),
        images: imagesLinks,
        shop: shop._id,
        seller: req.seller._id,
        priceDiscount: priceDiscount ? Number(priceDiscount) : undefined,
        subCategory,
        tags: tags || [],
        shipping: shipping || {},
        variations: variations || [],
        isMadeInCanada: isMadeInCanada || false,
        canadianCertification: canadianCertification || "",
      };

      const product = await Product.create(productData);
      res.status(201).json({
        success: true,
        product,
      });
    } catch (error) {
      console.error("Create product error:", {
        message: error.message,
        body: req.body,
        seller: req.seller?._id || "missing",
      });
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Get all products of a shop
router.get(
  "/get-all-products-shop/:id",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const products = await Product.find({ shop: req.params.id }).populate(
        "shop",
        "name"
      );
      res.status(200).json({
        success: true,
        products,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Delete product of a shop
router.delete(
  "/delete-shop-product/:id",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product) {
        return next(new ErrorHandler("Product not found", 404));
      }
      if (product.seller.toString() !== req.seller._id.toString()) {
        return next(
          new ErrorHandler(
            "Unauthorized: Product does not belong to seller",
            403
          )
        );
      }

      await Product.deleteOne({ _id: req.params.id });

      res.status(200).json({
        success: true,
        message: "Product deleted successfully",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Get all products
router.get(
  "/get-all-products",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const products = await Product.find()
        .sort({ createdAt: -1 })
        .populate("shop", "name");
      res.status(200).json({
        success: true,
        products,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Create or update product review
router.put(
  "/create-new-review",
  isAuthenticated,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { user, rating, comment, productId, orderId } = req.body;

      if (!rating || !comment || !productId || !orderId) {
        return next(
          new ErrorHandler("Missing required fields for review", 400)
        );
      }

      const product = await Product.findById(productId);
      if (!product) {
        return next(new ErrorHandler("Product not found", 404));
      }

      const order = await Order.findById(orderId);
      if (!order) {
        return next(new ErrorHandler("Order not found", 404));
      }

      const cartItem = order.cart.find(
        (item) => item._id.toString() === productId.toString()
      );
      if (!cartItem) {
        return next(new ErrorHandler("Product not found in order", 400));
      }

      const review = {
        user: req.user._id,
        name: req.user.name,
        rating: Number(rating),
        comment,
        createdAt: new Date(),
      };

      const existingReview = product.reviews.find(
        (rev) => rev.user.toString() === req.user._id.toString()
      );

      if (existingReview) {
        product.reviews = product.reviews.map((rev) =>
          rev.user.toString() === req.user._id.toString() ? review : rev
        );
      } else {
        product.reviews.push(review);
      }

      product.ratingsQuantity = product.reviews.length;
      product.ratingsAverage =
        product.reviews.reduce((acc, rev) => acc + rev.rating, 0) /
          product.ratingsQuantity || 0;

      await product.save({ validateBeforeSave: false });

      // Update order
      order.cart = order.cart.map((item) =>
        item._id.toString() === productId.toString()
          ? { ...item, isReviewed: true }
          : item
      );
      await order.save();

      res.status(200).json({
        success: true,
        message: "Review submitted successfully",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Get all products (admin)
router.get(
  "/admin-all-products",
  isAuthenticated,
  isAdmin("Admin"),
  catchAsyncErrors(async (req, res, next) => {
    try {
      const products = await Product.find()
        .sort({ createdAt: -1 })
        .populate("shop", "name");
      res.status(200).json({
        success: true,
        products,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

module.exports = router;
