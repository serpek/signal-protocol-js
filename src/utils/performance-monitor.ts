
// ===== PERFORMANCE MONITORING =====
// src/utils/performance-monitor.ts
import { Logger } from 'tslog';

const logger = new Logger({ name: 'PerformanceMonitor' });

export interface PerformanceMetrics {
    operation: string;
    duration: number;
    timestamp: number;
    metadata?: Record<string, any>;
}

export class PerformanceMonitor {
    private static metrics: PerformanceMetrics[] = [];
    private static timers: Map<string, number> = new Map();

    /**
     * Start timing an operation
     */
    static startTimer(operation: string): void {
        this.timers.set(operation, performance.now());
    }

    /**
     * End timing and record the metric
     */
    static endTimer(operation: string, metadata?: Record<string, any>): number {
        const startTime = this.timers.get(operation);
        if (!startTime) {
            logger.warn(`No timer found for operation: ${operation}`);
            return 0;
        }

        const duration = performance.now() - startTime;
        this.timers.delete(operation);

        const metric: PerformanceMetrics = {
            operation,
            duration,
            timestamp: Date.now(),
            metadata
        };

        this.metrics.push(metric);
        logger.debug(`${operation} took ${duration.toFixed(2)}ms`, metadata);

        // Keep only last 1000 metrics
        if (this.metrics.length > 1000) {
            this.metrics.shift();
        }

        return duration;
    }

    /**
     * Get average duration for an operation
     */
    static getAverageDuration(operation: string): number {
        const operationMetrics = this.metrics.filter(m => m.operation === operation);
        if (operationMetrics.length === 0) return 0;

        const sum = operationMetrics.reduce((acc, m) => acc + m.duration, 0);
        return sum / operationMetrics.length;
    }

    /**
     * Get all metrics
     */
    static getMetrics(): PerformanceMetrics[] {
        return [...this.metrics];
    }

    /**
     * Get metrics summary
     */
    static getSummary(): Record<string, {
        count: number;
        average: number;
        min: number;
        max: number;
        p95: number;
    }> {
        const summary: Record<string, any> = {};

        // Group metrics by operation
        const grouped = this.metrics.reduce((acc, m) => {
            if (!acc[m.operation]) acc[m.operation] = [];
            acc[m.operation].push(m.duration);
            return acc;
        }, {} as Record<string, number[]>);

        // Calculate statistics for each operation
        for (const [operation, durations] of Object.entries(grouped)) {
            const sorted = durations.sort((a, b) => a - b);
            const count = sorted.length;
            const sum = sorted.reduce((a, b) => a + b, 0);
            const p95Index = Math.floor(count * 0.95);

            summary[operation] = {
                count,
                average: sum / count,
                min: sorted[0],
                max: sorted[count - 1],
                p95: sorted[p95Index]
            };
        }

        return summary;
    }

    /**
     * Clear all metrics
     */
    static clear(): void {
        this.metrics = [];
        this.timers.clear();
    }
}
