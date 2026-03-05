const UserContext = require("../models/context.model");
const UserPreference = require("../models/preference.model");
const SuspiciousLogin = require("../models/suspiciousLogin.model");
const geoip = require("geoip-lite");
const { saveLogInfo } = require("../middlewares/logger/logInfo");
const formatCreatedAt = require("../utils/timeConverter");
const { sendSecurityAlert } = require("../services/email.service");
const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/email.service");

const types = {
  NO_CONTEXT_DATA: "no_context_data",
  MATCH: "match",
  BLOCKED: "blocked",
  SUSPICIOUS: "suspicious",
  ERROR: "error",
};
const getCurrentContextData = (req) => {
  const ip = req.clientIp || "unknown";
  const location = geoip.lookup(ip) || "unknown";
  const country = location.country ? location.country.toString() : "unknown";
  const city = location.city ? location.city.toString() : "unknown";
  const browser = req.useragent.browser
    ? `${req.useragent.browser} ${req.useragent.version}`
    : "unknown";
  const platform = req.useragent.platform
    ? req.useragent.platform.toString()
    : "unknown";
  const os = req.useragent.os ? req.useragent.os.toString() : "unknown";
  const device = req.useragent.device
    ? req.useragent.device.toString()
    : "unknown";

  const isMobile = req.useragent.isMobile || false;
  const isDesktop = req.useragent.isDesktop || false;
  const isTablet = req.useragent.isTablet || false;

  const deviceType = isMobile
    ? "Mobile"
    : isDesktop
    ? "Desktop"
    : isTablet
    ? "Tablet"
    : "unknown";

  return {
    ip,
    country,
    city,
    browser,
    platform,
    os,
    device,
    deviceType,
  };
};

const isTrustedDevice = (currentContextData, userContextData) =>
  Object.keys(userContextData).every(
    (key) => userContextData[key] === currentContextData[key]
  );

const isSuspiciousContextChanged = (oldContextData, newContextData) =>
  Object.keys(oldContextData).some(
    (key) => oldContextData[key] !== newContextData[key]
  );

const isOldDataMatched = (oldSuspiciousContextData, userContextData) =>
  Object.keys(oldSuspiciousContextData).every(
    (key) => oldSuspiciousContextData[key] === userContextData[key]
  );

const getOldSuspiciousContextData = (_id, currentContextData) =>
  SuspiciousLogin.findOne({
    user: _id,
    ip: currentContextData.ip,
    country: currentContextData.country,
    city: currentContextData.city,
    browser: currentContextData.browser,
    platform: currentContextData.platform,
    os: currentContextData.os,
    device: currentContextData.device,
    deviceType: currentContextData.deviceType,
  });

const addNewSuspiciousLogin = async (_id, existingUser, currentContextData) => {
  const newSuspiciousLogin = new SuspiciousLogin({
    user: _id,
    email: existingUser.email,
    ip: currentContextData.ip,
    country: currentContextData.country,
    city: currentContextData.city,
    browser: currentContextData.browser,
    platform: currentContextData.platform,
    os: currentContextData.os,
    device: currentContextData.device,
    deviceType: currentContextData.deviceType,
  });

  return await newSuspiciousLogin.save();
};
// ===== RISK CALCULATION =====

const calculateRiskScore = (trustedContext, currentContext) => {
  let score = 0;
  const reasons = [];

  if (trustedContext.ip !== currentContext.ip) {
    score += 30;
    reasons.push("NEW_IP");
  }

  if (trustedContext.country !== currentContext.country) {
    score += 40;
    reasons.push("NEW_COUNTRY");
  }

  if (trustedContext.city !== currentContext.city) {
    score += 10;
    reasons.push("NEW_CITY");
  }

  if (trustedContext.browser !== currentContext.browser) {
    score += 15;
    reasons.push("NEW_BROWSER");
  }

  if (trustedContext.device !== currentContext.device) {
    score += 25;
    reasons.push("NEW_DEVICE");
  }

  if (trustedContext.deviceType !== currentContext.deviceType) {
    score += 20;
    reasons.push("NEW_DEVICE_TYPE");
  }

  return { score, reasons };
};

const getRiskLevel = (score) => {
  if (score < 30) return "LOW";
  if (score < 70) return "MEDIUM";
  return "HIGH";
};
const verifyContextData = async (req, existingUser) => {
  try {
    const { _id } = existingUser;
    const userContextDataRes = await UserContext.findOne({ user: _id });

    if (!userContextDataRes) {
      return types.NO_CONTEXT_DATA;
    }

    const userContextData = {
      ip: userContextDataRes.ip,
      country: userContextDataRes.country,
      city: userContextDataRes.city,
      browser: userContextDataRes.browser,
      platform: userContextDataRes.platform,
      os: userContextDataRes.os,
      device: userContextDataRes.device,
      deviceType: userContextDataRes.deviceType,
    };

    const currentContextData = getCurrentContextData(req);
    const { score, reasons } = calculateRiskScore(
      userContextData,
      currentContextData
    );

    const riskLevel = getRiskLevel(score);

    let action =
      riskLevel === "LOW"
      ? "ALLOW"
      : riskLevel === "MEDIUM"
      ? "OTP_REQUIRED"
      : "STEP_UP_AUTH";

    let warning = false;
    let warningMessage = null;

    if (riskLevel === "MEDIUM") {
      warning = true;
      warningMessage = "Unusual login detected. OTP verification required.";
    }

    if (riskLevel === "HIGH") {
       warning = true;
       warningMessage = "High-risk login detected. Strong verification required.";

      await sendSecurityAlert(
        existingUser.email,
        currentContextData.city + ", " + currentContextData.country,
        currentContextData.device
      );
    }

    if (isTrustedDevice(currentContextData, userContextData)) {
      return {
        riskScore: 0,
        riskLevel: "LOW",
        reasons: [],
        action: "ALLOW",
        warning: false,
        warningMessage: null,
        currentContextData,
      };
    }

    const oldSuspiciousContextData = await getOldSuspiciousContextData(
      _id,
      currentContextData
    );

    if (oldSuspiciousContextData) {
      if (oldSuspiciousContextData.isBlocked) {
        return {
          riskScore: 90,
          riskLevel: "HIGH",
          reasons: ["PREVIOUSLY_FLAGGED_DEVICE"],
          action: "STEP_UP_AUTH",
          warning: true,
          warningMessage: "High-risk login detected. Strong verification required.",
          currentContextData,
        };
      }
      if (oldSuspiciousContextData.isTrusted) {
        return {
         riskScore: 10,
         riskLevel: "LOW",
         reasons: ["PREVIOUSLY_VERIFIED_DEVICE"],
         action: "ALLOW",
         warning: false,
         warningMessage: null,
         currentContextData,
        };
      }
    }

    let newSuspiciousData = {};
    if (
      oldSuspiciousContextData &&
      isSuspiciousContextChanged(oldSuspiciousContextData, currentContextData)
    ) {
      const {
        ip: suspiciousIp,
        country: suspiciousCountry,
        city: suspiciousCity,
        browser: suspiciousBrowser,
        platform: suspiciousPlatform,
        os: suspiciousOs,
        device: suspiciousDevice,
        deviceType: suspiciousDeviceType,
      } = oldSuspiciousContextData;

      if (
        suspiciousIp !== currentContextData.ip ||
        suspiciousCountry !== currentContextData.country ||
        suspiciousCity !== currentContextData.city ||
        suspiciousBrowser !== currentContextData.browser ||
        suspiciousDevice !== currentContextData.device ||
        suspiciousDeviceType !== currentContextData.deviceType ||
        suspiciousPlatform !== currentContextData.platform ||
        suspiciousOs !== currentContextData.os
      ) {
        //  Suspicious login data found, but it doesn't match the current context data, so we add new suspicious login data
        return {
           riskScore: score,
           riskLevel,
           reasons: [...reasons, "REPEATED_SUSPICIOUS_LOGIN"],
           action: "OTP_REQUIRED",
           warning: true,
           warningMessage: "Repeated suspicious login detected. OTP verification required.",
           currentContextData,
          };
        const res = await addNewSuspiciousLogin(
          _id,
          existingUser,
          currentContextData
        );

        newSuspiciousData = {
          time: formatCreatedAt(res.createdAt),
          ip: res.ip,
          country: res.country,
          city: res.city,
          browser: res.browser,
          platform: res.platform,
          os: res.os,
          device: res.device,
          deviceType: res.deviceType,
        };
      } else {
        // increase the unverifiedAttempts count by 1
        await SuspiciousLogin.findByIdAndUpdate(
          oldSuspiciousContextData._id,
          {
            $inc: { unverifiedAttempts: 1 },
          },
          { new: true }
        );
        //  If the unverifiedAttempts count is greater than or equal to 3, then we block the user
        if (oldSuspiciousContextData.unverifiedAttempts >= 3) {
          return {
           riskScore: score + 20,
           riskLevel: "HIGH",
           reasons: [...reasons, "MULTIPLE_FAILED_ATTEMPTS"],
           action: "STEP_UP_AUTH",
           warning: true,
           warningMessage: "Multiple suspicious attempts detected. Strong verification required.",
           currentContextData
          };
        }

        // Suspicious login data found, and it matches the current context data, so we return "already_exists"
        
      }
      } else if (
         oldSuspiciousContextData &&
         isOldDataMatched(oldSuspiciousContextData, currentContextData)
        ) {

           return {
             riskScore: 10,
             riskLevel: "LOW",
             reasons: ["KNOWN_SUSPICIOUS_DEVICE_NOW_TRUSTED"],
             action: "ALLOW",
             warning: false,
             warningMessage: null,
             currentContextData,
            };

    } else {
      //  No previous suspicious login data found, so we create a new one
      const res = await addNewSuspiciousLogin(
        _id,
        existingUser,
        currentContextData
      );

      newSuspiciousData = {
        time: formatCreatedAt(res.createdAt),
        id: res._id,
        ip: res.ip,
        country: res.country,
        city: res.city,
        browser: res.browser,
        platform: res.platform,
        os: res.os,
        device: res.device,
        deviceType: res.deviceType,
      };
    }

    const mismatchedProps = [];

    if (userContextData.ip !== newSuspiciousData.ip) {
      mismatchedProps.push("ip");
    }
    if (userContextData.browser !== newSuspiciousData.browser) {
      mismatchedProps.push("browser");
    }
    if (userContextData.device !== newSuspiciousData.device) {
      mismatchedProps.push("device");
    }
    if (userContextData.deviceType !== newSuspiciousData.deviceType) {
      mismatchedProps.push("deviceType");
    }
    if (userContextData.country !== newSuspiciousData.country) {
      mismatchedProps.push("country");
    }
    if (userContextData.city !== newSuspiciousData.city) {
      mismatchedProps.push("city");
    }

    return {
      riskScore: score,
      riskLevel,
      reasons,
      action,
      warning,
      warningMessage,
      currentContextData,
    };
  } catch (error) {
    return types.ERROR;
  }
};
const forgotPassword = async (req, res) => {
  try {

    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");

    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordExpire = Date.now() + 15 * 60 * 1000;

    await user.save();

    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;

    await sendPasswordResetEmail(user.email, resetLink);

    res.status(200).json({
      message: "Password reset email sent"
    });

  } catch (error) {

    res.status(500).json({
      message: "Server error"
    });

  }
};
const resetPassword = async (req, res) => {

  try {

    const resetToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({
      message: "Password reset successful"
    });

  } catch (error) {

    res.status(500).json({
      message: "Server error"
    });

  }

};
const addContextData = async (req, res) => {
  const userId = req.userId;
  const email = req.email;
  const ip = req.ip || "unknown";
  const location = geoip.lookup(ip) || "unknown";
  const country = location.country ? location.country.toString() : "unknown";
  const city = location.city ? location.city.toString() : "unknown";
  const browser = req.useragent.browser
    ? `${req.useragent.browser} ${req.useragent.version}`
    : "unknown";
  const platform = req.useragent.platform
    ? req.useragent.platform.toString()
    : "unknown";
  const os = req.useragent.os ? req.useragent.os.toString() : "unknown";
  const device = req.useragent.device
    ? req.useragent.device.toString()
    : "unknown";

  const isMobile = req.useragent.isMobile || false;
  const isDesktop = req.useragent.isDesktop || false;
  const isTablet = req.useragent.isTablet || false;

  const deviceType = isMobile
    ? "Mobile"
    : isDesktop
    ? "Desktop"
    : isTablet
    ? "Tablet"
    : "unknown";

  const newUserContext = new UserContext({
    user: userId,
    email,
    ip,
    country,
    city,
    browser,
    platform,
    os,
    device,
    deviceType,
  });

  try {
    await newUserContext.save();
    res.status(200).json({
      message: "Email verification process was successful",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route GET /auth/context-data/primary
 */
const getAuthContextData = async (req, res) => {
  try {
    const result = await UserContext.findOne({ user: req.userId });

    if (!result) {
      return res.status(404).json({ message: "Not found" });
    }

    const userContextData = {
      firstAdded: formatCreatedAt(result.createdAt),
      ip: result.ip,
      country: result.country,
      city: result.city,
      browser: result.browser,
      platform: result.platform,
      os: result.os,
      device: result.device,
      deviceType: result.deviceType,
    };

    res.status(200).json(userContextData);
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route GET /auth/context-data/trusted
 */
const getTrustedAuthContextData = async (req, res) => {
  try {
    const result = await SuspiciousLogin.find({
      user: req.userId,
      isTrusted: true,
      isBlocked: false,
    });

    const trustedAuthContextData = result.map((item) => {
      return {
        _id: item._id,
        time: formatCreatedAt(item.createdAt),
        ip: item.ip,
        country: item.country,
        city: item.city,
        browser: item.browser,
        platform: item.platform,
        os: item.os,
        device: item.device,
        deviceType: item.deviceType,
      };
    });

    res.status(200).json(trustedAuthContextData);
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route GET /auth/context-data/blocked
 */
const getBlockedAuthContextData = async (req, res) => {
  try {
    const result = await SuspiciousLogin.find({
      user: req.userId,
      isBlocked: true,
      isTrusted: false,
    });

    const blockedAuthContextData = result.map((item) => {
      return {
        _id: item._id,
        time: formatCreatedAt(item.createdAt),
        ip: item.ip,
        country: item.country,
        city: item.city,
        browser: item.browser,
        platform: item.platform,
        os: item.os,
        device: item.device,
        deviceType: item.deviceType,
      };
    });

    res.status(200).json(blockedAuthContextData);
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route GET /auth/user-preferences
 */
const getUserPreferences = async (req, res) => {
  try {
    const userPreferences = await UserPreference.findOne({ user: req.userId });

    if (!userPreferences) {
      return res.status(404).json({ message: "Not found" });
    }

    res.status(200).json(userPreferences);
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route DELETE /auth/context-data/:contextId
 */
const deleteContextAuthData = async (req, res) => {
  try {
    const contextId = req.params.contextId;

    await SuspiciousLogin.deleteOne({ _id: contextId });

    res.status(200).json({
      message: "Data deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route PATCH /auth/context-data/block/:contextId
 */
const blockContextAuthData = async (req, res) => {
  try {
    const contextId = req.params.contextId;

    await SuspiciousLogin.findOneAndUpdate(
      { _id: contextId },
      { $set: { isBlocked: true, isTrusted: false } },
      { new: true }
    );

    res.status(200).json({
      message: "Blocked successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

/**
 * @route PATCH /auth/context-data/unblock/:contextId
 */
const unblockContextAuthData = async (req, res) => {
  try {
    const contextId = req.params.contextId;

    await SuspiciousLogin.findOneAndUpdate(
      { _id: contextId },
      { $set: { isBlocked: false, isTrusted: true } },
      { new: true }
    );

    res.status(200).json({
      message: "Unblocked successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
    });
  }
};

module.exports = {
  verifyContextData,
  addContextData,
  getAuthContextData,
  getUserPreferences,
  getTrustedAuthContextData,
  getBlockedAuthContextData,
  deleteContextAuthData,
  blockContextAuthData,
  unblockContextAuthData,
  types,
};
