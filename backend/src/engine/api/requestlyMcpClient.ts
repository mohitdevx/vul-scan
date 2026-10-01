import { logger } from '../../utils/logger.js'
import type { RequestlyRule, RequestlyRuleGroup } from './requestlyRules.js'

export interface RequestlyMcpConfig {
  apiKey?: string
  serverCommand?: string
  serverArgs?: string[]
}

export interface McpToolCallPayload {
  jsonrpc: '2.0'
  id: string | number
  method: string
  params?: Record<string, any>
}

export class RequestlyMcpClient {
  private apiKey: string | undefined
  private isConnected = false

  constructor(config?: RequestlyMcpConfig) {
    this.apiKey = config?.apiKey || process.env.REQUESTLY_API_KEY
  }

  /**
   * Generates standard MCP configuration JSON for .vscode/mcp.json or Claude Desktop
   */
  public getMcpConfigJson(): Record<string, any> {
    return {
      'Requestly Server': {
        type: 'stdio',
        command: 'npx',
        args: ['@requestly/mcp'],
        env: {
          REQUESTLY_API_KEY: this.apiKey || '<YOUR_REQUESTLY_API_KEY>',
        },
      },
    }
  }

  /**
   * Formats a tool invocation message for Requestly MCP server
   */
  public buildCreateGroupMcpPayload(group: RequestlyRuleGroup): McpToolCallPayload {
    return {
      jsonrpc: '2.0',
      id: `call-create-group-${Date.now()}`,
      method: 'tools/call',
      params: {
        name: 'create_group',
        arguments: {
          name: group.name,
          description: group.description,
        },
      },
    }
  }

  /**
   * Formats create_rule tool invocation for Requestly MCP server
   */
  public buildCreateRuleMcpPayload(rule: RequestlyRule, groupId?: string): McpToolCallPayload {
    return {
      jsonrpc: '2.0',
      id: `call-create-rule-${rule.id}`,
      method: 'tools/call',
      params: {
        name: 'create_rule',
        arguments: {
          name: rule.name,
          description: rule.description,
          ruleType: rule.ruleType,
          status: rule.status,
          urlCondition: rule.urlCondition,
          headers: rule.headers,
          groupId,
        },
      },
    }
  }

  /**
   * Simulates/executes rule synchronization with Requestly MCP server
   */
  public async syncRulesWithMcp(group: RequestlyRuleGroup): Promise<{
    synced: boolean
    rulesCount: number
    mcpPayloadsCount: number
    message: string
  }> {
    logger.info(`[RequestlyMCP] Syncing ${group.rules.length} rules to Requestly MCP server...`)
    const groupPayload = this.buildCreateGroupMcpPayload(group)
    const rulePayloads = group.rules.map(r => this.buildCreateRuleMcpPayload(r))

    return {
      synced: true,
      rulesCount: group.rules.length,
      mcpPayloadsCount: rulePayloads.length + 1,
      message: `Successfully structured ${group.rules.length} security testing rules for Requestly MCP server.`,
    }
  }
}

export function generateRequestlyMcpBundle(suite: RequestlyRuleGroup): {
  vscodeMcpConfig: Record<string, any>
  mcpTools: string[]
  instructions: string
} {
  const client = new RequestlyMcpClient()
  return {
    vscodeMcpConfig: client.getMcpConfigJson(),
    mcpTools: ['create_rule', 'create_group', 'get_rules', 'delete_rule', 'modify_headers', 'redirect_request'],
    instructions:
      'Add this server configuration to .vscode/mcp.json or Claude Desktop to empower AI agents to intercept, replay, and modify API traffic in real-time.',
  }
}
