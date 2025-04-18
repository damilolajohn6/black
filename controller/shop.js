require("dotenv").config();
const express = require("express");
const { body } = require("express-validator");
const router = express.Router();
const jwt = require("jsonwebtoken");
const sendMail = require("../utils/sendMail");
const Shop = require("../model/shop");
const { isAuthenticated, isSeller, isAdmin } = require("../middleware/auth");
const cloudinary = require("cloudinary");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const ErrorHandler = require("../utils/ErrorHandler");
const sendShopToken = require("../utils/shopToken");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// create shop
router.post(
  "/create-shop",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
    body("name").notEmpty().withMessage("Shop name is required"),
    body("address").notEmpty().withMessage("Address is required"),
    body("zipCode")
      .isNumeric()
      .withMessage("Zip code must be a number")
      .notEmpty()
      .withMessage("Zip code is required"),
    body("phone.countryCode")
      .optional()
      .matches(/^\+\d{1,3}$/)
      .withMessage("Invalid country code (e.g., +1, +44)"),
    body("phone.number")
      .optional()
      .matches(/^\d{7,15}$/)
      .withMessage("Phone number must be 7-15 digits"),
  ],
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { name, email, password, avatar, address, zipCode, phone } =
        req.body;
      const shopEmail = await Shop.findOne({ email });

      if (shopEmail) {
        return next(
          new ErrorHandler("Shop with this email already exists", 400)
        );
      }

      const shop = {
        name,
        email,
        password,
        address,
        zipCode,
        phoneNumber:
          phone && phone.countryCode && phone.number ? phone : undefined,
        avatar: avatar || { public_id: "", url: "" },
        role: "Seller",
        verificationOtp: Math.floor(100000 + Math.random() * 900000).toString(),
        verificationOtpExpiry: Date.now() + 10 * 60 * 1000,
        isVerified: false,
      };

      try {
        await sendMail({
          email: shop.email,
          subject: "Activate your shop account",
          message: `Hello ${shop.name}, your OTP to activate your shop account is ${shop.verificationOtp}. It expires in 10 minutes.`,
        });

        await Shop.create(shop);

        res.status(201).json({
          success: true,
          message: `Please check your email (${shop.email}) to activate your shop account with the OTP!`,
        });
      } catch (error) {
        console.log("CREATE SHOP ERROR:", error);
        return next(new ErrorHandler(error.message, 500));
      }
    } catch (error) {
      console.log("CREATE SHOP ERROR:", error);
      return next(new ErrorHandler(error.message, 400));
    }
  })
);

// Activate shop
router.post(
  "/activation",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { email, otp } = req.body;
      if (!email || !otp) {
        return next(new ErrorHandler("Email and OTP are required", 400));
      }
      const shop = await Shop.findOne({ email });
      if (!shop) {
        return next(new ErrorHandler("Shop not found", 400));
      }
      if (shop.isVerified) {
        return next(new ErrorHandler("Shop already verified", 400));
      }
      if (
        shop.verificationOtp !== otp ||
        shop.verificationOtpExpiry < Date.now()
      ) {
        return next(new ErrorHandler("Invalid or expired OTP", 400));
      }
      shop.isVerified = true;
      shop.verificationOtp = undefined;
      shop.verificationOtpExpiry = undefined;
      await shop.save();
      const token = shop.getJwtToken();
      sendShopToken(shop, 201, res, token);
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// Resend OTP
router.post(
  "/resend-otp",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { email } = req.body;

      if (!email) {
        return next(new ErrorHandler("Email is required", 400));
      }

      const shop = await Shop.findOne({ email });

      if (!shop) {
        return next(new ErrorHandler("Shop not found", 400));
      }

      if (shop.isVerified) {
        return next(new ErrorHandler("Shop already verified", 400));
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiry = Date.now() + 10 * 60 * 1000;

      shop.verificationOtp = otp;
      shop.verificationOtpExpiry = otpExpiry;
      await shop.save();

      try {
        await sendMail({
          email: shop.email,
          subject: "Activate your shop account - New OTP",
          message: `Hello ${shop.name}, your new OTP to activate your shop account is ${otp}. It expires in 10 minutes.`,
        });

        res.status(200).json({
          success: true,
          message: `A new OTP has been sent to ${shop.email}.`,
        });
      } catch (error) {
        console.log("RESEND OTP ERROR:", error);
        return next(new ErrorHandler("Failed to send OTP email", 500));
      }
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// login shop
router.post(
  "/login-shop",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return next(new ErrorHandler("Please provide all fields!", 400));
      }
      const shop = await Shop.findOne({ email }).select("+password");
      if (!shop) {
        return next(new ErrorHandler("Shop doesn't exist!", 400));
      }
      if (!shop.isVerified) {
        return next(
          new ErrorHandler("Please verify your shop account first!", 400)
        );
      }
      const isPasswordValid = await shop.comparePassword(password);
      if (!isPasswordValid) {
        return next(new ErrorHandler("Invalid credentials", 400));
      }
      const token = shop.getJwtToken();
      sendShopToken(shop, 201, res, token);
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// load shop
router.get(
  "/getshop",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const shop = await Shop.findById(req.seller.id);
      if (!shop) {
        return next(new ErrorHandler("Shop not found", 404));
      }
      res.status(200).json({
        success: true,
        seller: shop,
        token: req.seller.token,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// log out from shop
router.get(
  "/logout",
  catchAsyncErrors(async (req, res, next) => {
    try {
      res.cookie("seller_token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      });
      res.status(200).json({
        success: true,
        message: "Shop logged out successfully",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// get shop info
router.get(
  "/get-shop-info/:id",
  catchAsyncErrors(async (req, res, next) => {
    try {
      const shop = await Shop.findById(req.params.id);
      if (!shop) {
        return next(new ErrorHandler("Shop not found", 404));
      }
      res.set("Cache-Control", "no-store");
      res.status(200).json({
        success: true,
        shop,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update shop profile picture
router.put(
  "/update-shop-avatar",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      let existsSeller = await Shop.findById(req.seller.id);
      if (existsSeller.avatar.public_id) {
        await cloudinary.v2.uploader.destroy(existsSeller.avatar.public_id);
      }
      const myCloud = await cloudinary.v2.uploader.upload(req.body.avatar, {
        folder: "avatars",
        width: 150,
      });
      existsSeller.avatar = {
        public_id: myCloud.public_id,
        url: myCloud.secure_url,
      };
      await existsSeller.save();
      res.status(200).json({
        success: true,
        seller: existsSeller,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update seller info
router.put(
  "/update-seller-info",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { name, description, address, phoneNumber, zipCode } = req.body;
      const shop = await Shop.findById(req.seller.id);
      if (!shop) {
        return next(new ErrorHandler("Shop not found", 400));
      }
      shop.name = name;
      shop.description = description;
      shop.address = address;
      shop.phoneNumber = phoneNumber;
      shop.zipCode = zipCode;
      await shop.save();
      res.status(201).json({
        success: true,
        shop,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// all sellers --- for admin
router.get(
  "/admin-all-sellers",
  isAuthenticated,
  isAdmin("Admin"),
  catchAsyncErrors(async (req, res, next) => {
    try {
      const sellers = await Shop.find().sort({ createdAt: -1 });
      res.status(201).json({
        success: true,
        sellers,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// delete seller ---admin
router.delete(
  "/delete-seller/:id",
  isAuthenticated,
  isAdmin("Admin"),
  catchAsyncErrors(async (req, res, next) => {
    try {
      const seller = await Shop.findById(req.params.id);
      if (!seller) {
        return next(
          new ErrorHandler("Seller is not available with this id", 400)
        );
      }
      await Shop.findByIdAndDelete(req.params.id);
      res.status(201).json({
        success: true,
        message: "Seller deleted successfully!",
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// update seller withdraw methods --- sellers
router.put(
  "/update-payment-methods",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const { withdrawMethod } = req.body;
      const seller = await Shop.findByIdAndUpdate(req.seller.id, {
        withdrawMethod,
      });
      res.status(201).json({
        success: true,
        seller,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

// delete seller withdraw methods --- only seller
router.delete(
  "/delete-withdraw-method/",
  isSeller,
  catchAsyncErrors(async (req, res, next) => {
    try {
      const seller = await Shop.findById(req.seller.id);
      if (!seller) {
        return next(new ErrorHandler("Seller not found with this id", 400));
      }
      seller.withdrawMethod = null;
      await seller.save();
      res.status(201).json({
        success: true,
        seller,
      });
    } catch (error) {
      return next(new ErrorHandler(error.message, 500));
    }
  })
);

module.exports = router;
