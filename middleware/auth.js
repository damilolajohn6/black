const jwt = require("jsonwebtoken");
const ErrorHandler = require("../utils/ErrorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");
const User = require("../model/user");
const Shop = require("../model/shop");

exports.isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const { token } = req.cookies;
  if (!token) {
    return next(new ErrorHandler("Please login to continue", 401));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);
    if (!req.user) {
      return next(new ErrorHandler("User not found", 404));
    }
    next();
  } catch (error) {
    console.error("isAuthenticated error:", {
      message: error.message,
      token: token ? "present" : "missing",
    });
    return next(new ErrorHandler("Invalid or expired token", 401));
  }
});

exports.isSeller = catchAsyncErrors(async (req, res, next) => {
  let token = req.cookies.seller_token;
  if (!token && req.headers.authorization?.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    console.error("isSeller: No seller_token found", {
      cookies: !!req.cookies.seller_token,
      authorization: !!req.headers.authorization,
    });
    return next(new ErrorHandler("Please login as a seller to continue", 401));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.seller = await Shop.findById(decoded.id);
    if (!req.seller) {
      console.error("isSeller: Shop not found for ID:", decoded.id);
      return next(new ErrorHandler("Seller not found", 404));
    }
    if (!req.seller.isVerified) {
      console.error("isSeller: Shop not verified for ID:", decoded.id);
      return next(new ErrorHandler("Please verify your shop account", 403));
    }
    req.seller.token = token; // Ensure token is available downstream
    next();
  } catch (error) {
    console.error("isSeller error:", {
      message: error.message,
      token: token ? "present" : "missing",
      decoded_id: error.name === "JsonWebTokenError" ? "invalid" : "unknown",
    });
    return next(new ErrorHandler("Invalid or expired seller token", 401));
  }
});

exports.isAdmin = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return next(
        new ErrorHandler(
          `${req.user?.role || "User"} is not allowed to access this resource!`,
          403
        )
      );
    }
    next();
  };
};
