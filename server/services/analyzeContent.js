const { google } = require("googleapis");
const { saveLogInfo } = require("../middlewares/logger/logInfo");
const Config = require("../models/config.model");
const axios = require("axios");

const analyzeTextWithPerspectiveAPI = async (
  content,
  API_KEY,
  DISCOVERY_URL,
  timeout
) => {
  const SCORE_THRESHOLD = 0.5;

  if (!API_KEY || !DISCOVERY_URL) {
    throw new Error("Perspective API URL or API Key not set");
  }

  try {
    const client = await google.discoverAPI(DISCOVERY_URL);

    const analyzeRequest = {
      comment: {
        text: content,
      },
      requestedAttributes: {
        // SPAM: {},
        // UNSUBSTANTIAL: {},
        INSULT: {},
        PROFANITY: {},
        THREAT: {},
        SEXUALLY_EXPLICIT: {},
        IDENTITY_ATTACK: {},
        TOXICITY: {},
      },
    };

    const responsePromise = client.comments.analyze({
      key: API_KEY,
      resource: analyzeRequest,
    });

    const timeoutPromise = new Promise((resolve, reject) => {
      setTimeout(() => {
        reject(new Error("Request timed out"));
      }, timeout);
    });

    const response = await Promise.race([responsePromise, timeoutPromise]);

    const summaryScores = {};
    for (const attribute in response.data.attributeScores) {
      const summaryScore =
        response.data.attributeScores[attribute].summaryScore.value;
      if (summaryScore >= SCORE_THRESHOLD) {
        summaryScores[attribute] = summaryScore;
      }
    }

    return summaryScores;
  } catch (error) {
    throw new Error(`Error analyzing text: ${error.message}`);
  }
};

const analyzeContent = async (req, res, next) => {
  try {
    const { content } = req.body;

    // 🔹 1. Call your classifier API
    const classifierResponse = await axios.post(
      "https://classifier-api-s1ju.onrender.com/classify",
      { text: content }
    );

    const categories = classifierResponse.data.response.categories;

    // Example: block if low confidence or something weird
    if (!categories || categories.length === 0) {
      return res.status(500).json({ message: "Classification failed" });
    }

    // 🔹 2. OPTIONAL: Risk-based logic
    const riskResponse = await axios.post(
      "https://classifier-api-s1ju.onrender.com/predict-risk",
      {
        location: req.ip || "India",
        device: req.headers["user-agent"] || "",
        failedAttempts: 0,
      }
    );

    const risk = riskResponse.data.risk;

    if (risk === "high") {
      return res.status(403).json({
        message: "High risk activity detected",
      });
    }

    // 🔹 3. Continue flow
    next();
  } catch (error) {
    console.error("Classifier Error:", error.message);

    // IMPORTANT: don't break post creation
    next();
  }
};

module.exports = analyzeContent;
