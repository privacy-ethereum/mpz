// Main application entry point for WASM benchmarks

import init, * as wasm from '../pkg/mpz_wasm_bench.js';
import * as bench from './bench.js';

// Capture console logs for headless runner
window.__consoleLogs = [];

// Wrap all console methods
const wrapConsole = (method) => {
    const original = console[method];
    console[method] = (...args) => {
        window.__consoleLogs.push(`[${method}] ${args.map(a => String(a)).join(' ')}`);
        original.apply(console, args);
    };
};

['log', 'info', 'warn', 'error', 'debug'].forEach(wrapConsole);

// Mark that wrapper is installed
window.__consoleLogs.push('[wrapper] Console wrapper installed');

const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
const runAllBtn = document.getElementById('runAll');
const runGarbleCoreBtn = document.getElementById('runGarbleCore');
const iterationsInput = document.getElementById('iterations');
const samplesInput = document.getElementById('samples');

function getConfig() {
    return {
        iterations: parseInt(iterationsInput.value) || 100,
        samples: parseInt(samplesInput.value) || 10,
    };
}

function setStatus(msg, isError = false) {
    statusEl.textContent = msg;
    statusEl.className = isError ? 'error' : 'success';
}

function disableButtons(disabled) {
    runAllBtn.disabled = disabled;
    runGarbleCoreBtn.disabled = disabled;
}

async function runBenchmarks(type, filter = null, concurrency = 8) {
    const config = getConfig();
    disableButtons(true);
    const filterInfo = filter ? ` [${filter.length} selected]` : '';
    const concurrencyInfo = `, ${concurrency} threads`;
    setStatus(`Running ${type} benchmarks${filterInfo} (${config.iterations} iterations, ${config.samples} samples${concurrencyInfo})...`);
    outputEl.textContent = '';

    // Use setTimeout to allow UI update before blocking
    await new Promise(r => setTimeout(r, 50));

    try {
        let results;
        if (type === 'all') {
            results = await bench.runAllBenchmarks(config.iterations, config.samples, filter, concurrency);
        } else if (type === 'garble_core') {
            results = { garble_core: bench.runGarbleCoreBenchmarks(config.iterations, config.samples) };
        }

        const formatted = bench.formatResults(results);
        outputEl.textContent = formatted;
        setStatus('Benchmarks complete!');

        // Store results for chromiumoxide to retrieve
        window.__benchResults = { results, formatted };
    } catch (e) {
        setStatus(`Error: ${e.message}`, true);
        outputEl.textContent = e.stack || e.toString();
    } finally {
        disableButtons(false);
    }
}

// Initialize
async function main() {
    try {
        console.log('main() started');
        setStatus('Initializing WASM...');
        console.log('Calling init()...');
        await init();
        console.log('init() complete');

        bench.init(wasm);
        setStatus('WASM loaded. Ready to run benchmarks.');
        disableButtons(false);

        // Check for auto-run (for chromiumoxide)
        const params = new URLSearchParams(window.location.search);
        if (params.get('autorun') === 'true') {
            const iterations = parseInt(params.get('iterations')) || 100;
            const samples = parseInt(params.get('samples')) || 10;
            const benchmarksParam = params.get('benchmarks');
            const filter = benchmarksParam ? benchmarksParam.split(',').filter(s => s) : null;
            const concurrencyParam = params.get('concurrency');
            const concurrency = concurrencyParam ? parseInt(concurrencyParam) : (navigator.hardwareConcurrency || 8);

            // Only initialize thread pool if MT benchmarks are selected
            const needsMT = bench.needsThreadPool(filter, concurrency);
            if (needsMT) {
                console.log(`Initializing thread pool with ${concurrency} threads...`);
                setStatus(`Initializing thread pool (${concurrency} threads)...`);
                await wasm.init_thread_pool(concurrency);
                console.log('Thread pool initialized');
            } else {
                console.log('Skipping thread pool init (no MT benchmarks selected)');
            }

            console.log(`Autorun triggered: iterations=${iterations}, samples=${samples}, benchmarks=${benchmarksParam}, concurrency=${concurrency}`);
            iterationsInput.value = iterations;
            samplesInput.value = samples;
            console.log('Starting benchmarks...');
            await runBenchmarks('all', filter, concurrency);
            console.log('Benchmarks finished');
        }
    } catch (e) {
        setStatus(`Failed to load WASM: ${e.message}`, true);
        outputEl.textContent = e.stack || e.toString();
        window.__benchError = e.message || e.toString();
    }
}

// Global error handler
window.onerror = (msg, url, line, col, error) => {
    window.__benchError = `${msg} at ${url}:${line}:${col}`;
    setStatus(`Error: ${msg}`, true);
};

window.onunhandledrejection = (event) => {
    window.__benchError = event.reason?.message || event.reason?.toString() || 'Unknown promise rejection';
    setStatus(`Error: ${window.__benchError}`, true);
};

runAllBtn.addEventListener('click', () => runBenchmarks('all'));
runGarbleCoreBtn.addEventListener('click', () => runBenchmarks('garble_core'));

// Expose for chromiumoxide
window.runBenchmark = async (config) => {
    const iterations = config?.iterations || 100;
    const samples = config?.samples || 10;
    iterationsInput.value = iterations;
    samplesInput.value = samples;
    await runBenchmarks('all');
    return window.__benchResults;
};

main();
