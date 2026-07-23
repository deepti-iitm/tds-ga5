import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json());

// Render automatically sets process.env.PORT, defaulting to 3000 locally
const PORT = process.env.PORT || 3000;
const REG_EMAIL = "23f2005361@ds.study.iitm.ac.in";

// Main MCP Endpoint
app.post('/mcp', (req, res) => {
  const { jsonrpc, method, id } = req.body;

  // 1. Handle Handshake
  if (method === 'initialize') {
    return res.json({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "exam-server", version: "1.0.0" }
      }
    });
  }

  // 2. Handle Tools Listing
  if (method === 'tools/list') {
    return res.json({
      jsonrpc: "2.0",
      id,
      result: {
        tools: [
          {
            name: "solve_challenge",
            description: "Solves the live exam challenge",
            inputSchema: { type: "object", properties: {} }
          }
        ]
      }
    });
  }

  // 3. Handle Tool Call execution
  if (method === 'tools/call') {
    const toolName = req.body.params?.name;

    if (toolName === 'solve_challenge') {
      // Read challenge strictly from the incoming HTTP request headers
      const challenge = req.headers['x-exam-challenge'];

      if (!challenge) {
        return res.status(400).json({
          jsonrpc: "2.0", id, error: { code: -32602, message: "Missing X-Exam-Challenge header" }
        });
      }

      // Compute SHA-256("${challenge}:${normalizedEmail}")
      const dataToHash = `${challenge}:${REG_EMAIL}`;
      const fullHash = crypto.createHash('sha256').update(dataToHash).digest('hex');
      
      // Extract the first 16 lowercase hex characters
      const shortResult = fullHash.substring(0, 16);

      // Return the standard MCP text content block response
      return res.json({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: shortResult
            }
          ]
        }
      });
    }
  }

  // Default fallback response for unhandled notifications/methods
  return res.json({ jsonrpc: "2.0", id, result: {} });
});

app.listen(PORT, () => {
  console.log(`MCP Server running on port ${PORT}`);
});
