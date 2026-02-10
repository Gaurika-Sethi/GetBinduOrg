/**
 * Direct Agent API Message Handler
 * Simplified implementation that directly calls agent API without backend complexity
 * Based on working patterns from bindu/ui/static/app.js
 */

import type { MessageUpdate } from '$lib/types/MessageUpdate';
import { MessageUpdateType, MessageUpdateStatus } from '$lib/types/MessageUpdate';

const AGENT_BASE_URL = 'http://localhost:3773';

interface AgentMessage {
	role: 'user' | 'agent';
	parts: Array<{ kind: 'text'; text: string }>;
	kind: 'message';
	messageId: string;
	contextId: string;
	taskId: string;
}

interface AgentTask {
	id: string;
	context_id: string;
	kind: 'task';
	status: {
		state: 'submitted' | 'working' | 'input-required' | 'completed' | 'failed' | 'canceled';
		timestamp: string;
	};
	history: Array<{
		kind: 'message';
		role: 'user' | 'assistant' | 'agent';
		parts: Array<{ kind: 'text'; text: string }>;
	}>;
	artifacts: Array<{
		kind: string;
		parts?: Array<{ kind: 'text'; text: string }>;
		text?: string;
	}>;
	metadata?: Record<string, unknown>;
}

/**
 * Generate a UUID v4
 */
function generateId(): string {
	return crypto.randomUUID();
}

/**
 * Get auth token from localStorage
 */
function getAuthToken(): string | null {
	if (typeof window === 'undefined') return null;
	return localStorage.getItem('bindu_oauth_token');
}

/**
 * Extract text from task (artifacts or history)
 */
function extractTextFromTask(task: AgentTask): string {
	// Try artifacts first (completed tasks)
	if (task.artifacts && task.artifacts.length > 0) {
		const textParts: string[] = [];
		for (const artifact of task.artifacts) {
			if (artifact.parts) {
				for (const part of artifact.parts) {
					if (part.kind === 'text' && part.text) {
						textParts.push(part.text);
					}
				}
			} else if (artifact.text) {
				textParts.push(artifact.text);
			}
		}
		if (textParts.length > 0) return textParts.join('\n');
	}

	// Fallback to history (input-required, etc.)
	if (task.history && task.history.length > 0) {
		for (let i = task.history.length - 1; i >= 0; i--) {
			const msg = task.history[i];
			if (msg.role === 'assistant' || msg.role === 'agent') {
				if (msg.parts) {
					for (const part of msg.parts) {
						if (part.kind === 'text' && part.text) {
							return part.text;
						}
					}
				}
			}
		}
	}

	return '';
}

/**
 * Send message to agent and poll for completion
 * Returns an async generator that yields MessageUpdate objects
 */
export async function* sendAgentMessage(
	message: string,
	contextId?: string,
	abortSignal?: AbortSignal
): AsyncGenerator<MessageUpdate, void, void> {
	const token = getAuthToken();
	const headers: Record<string, string> = {
		'Content-Type': 'application/json'
	};
	
	if (token) {
		headers['Authorization'] = `Bearer ${token}`;
	}

	// Generate IDs
	const messageId = generateId();
	const taskId = generateId();
	// Pad contextId to 32 chars if it's a MongoDB ObjectId (24 chars)
	const newContextId = contextId 
		? (contextId.length === 24 ? contextId.padEnd(32, '0') : contextId)
		: generateId();

	// Build message
	const agentMessage: AgentMessage = {
		role: 'user',
		parts: [{ kind: 'text', text: message }],
		kind: 'message',
		messageId,
		contextId: newContextId,
		taskId
	};

	// Step 1: Send message
	yield { type: MessageUpdateType.Status, status: MessageUpdateStatus.Started };

	try {
		const response = await fetch(`${AGENT_BASE_URL}/`, {
			method: 'POST',
			headers,
			body: JSON.stringify({
				jsonrpc: '2.0',
				method: 'message/send',
				params: {
					message: agentMessage,
					configuration: {
						acceptedOutputModes: ['application/json']
					}
				},
				id: generateId()
			}),
			signal: abortSignal
		});

		if (!response.ok) {
			const errorText = await response.text().catch(() => 'Unknown error');
			throw new Error(`Agent request failed: ${response.status} - ${errorText}`);
		}

		const result = await response.json();
		
		if (result.error) {
			throw new Error(result.error.message || 'Agent error');
		}

		const task = result.result as AgentTask;
		const submittedTaskId = task.id;

		// Step 2: Poll for completion
		const pollInterval = 1000; // 1 second
		const maxAttempts = 300; // 5 minutes

		for (let attempt = 0; attempt < maxAttempts; attempt++) {
			if (abortSignal?.aborted) {
				throw new Error('Request aborted');
			}

			// Wait before polling (except first attempt)
			if (attempt > 0) {
				await new Promise(resolve => setTimeout(resolve, pollInterval));
			}

			// Poll task status
			const statusResponse = await fetch(`${AGENT_BASE_URL}/`, {
				method: 'POST',
				headers,
				body: JSON.stringify({
					jsonrpc: '2.0',
					method: 'tasks/get',
					params: { taskId: submittedTaskId },
					id: generateId()
				}),
				signal: abortSignal
			});

			if (!statusResponse.ok) {
				continue; // Retry on error
			}

			const statusResult = await statusResponse.json();
			
			if (statusResult.error) {
				throw new Error(statusResult.error.message || 'Task status error');
			}

			const currentTask = statusResult.result as AgentTask;
			const taskState = currentTask.status.state;

			// Check if task is complete or needs input
			if (taskState === 'completed' || taskState === 'input-required') {
				const text = extractTextFromTask(currentTask);
				
				// Yield final answer directly (no stream tokens needed)
				// The FinalAnswer will set message.content which the UI will render
				yield { 
					type: MessageUpdateType.FinalAnswer, 
					text: text || '', 
					interrupted: false 
				};
				return;
			} else if (taskState === 'failed') {
				throw new Error(`Task failed: ${currentTask.metadata?.error || 'Unknown error'}`);
			} else if (taskState === 'canceled') {
				throw new Error('Task was canceled');
			}
			// Otherwise continue polling (working, submitted)
		}

		throw new Error('Task polling timeout');

	} catch (error) {
		yield {
			type: MessageUpdateType.Status,
			status: MessageUpdateStatus.Error,
			message: error instanceof Error ? error.message : 'Unknown error'
		};
		throw error;
	}
}
