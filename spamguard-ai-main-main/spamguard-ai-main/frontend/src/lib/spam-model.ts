import * as tf from '@tensorflow/tfjs';
import { SPAM_dataset } from './spam-dataset';

// Constants
const VOCAB_SIZE = 500;
const MAX_LEN = 20;

export class SpamModel {
    private model: tf.Sequential | null = null;
    private vocabulary: Map<string, number> = new Map();
    private isTraining = false;

    constructor() {
        this.buildVocabulary();
    }

    private cleanText(text: string): string[] {
        return text
            .toLowerCase()
            .replace(/[^\w\s]/g, '')
            .split(/\s+/)
            .filter(w => w.length > 2);
    }

    private buildVocabulary() {
        const wordCounts = new Map<string, number>();

        SPAM_dataset.forEach(item => {
            const words = this.cleanText(item.text);
            words.forEach(word => {
                wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
            });
        });

        // Sort by frequency and take top N
        const sortedWords = Array.from(wordCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, VOCAB_SIZE);

        sortedWords.forEach((item, index) => {
            this.vocabulary.set(item[0], index + 1); // 1-based index, 0 is padding
        });
    }

    private textToSequence(text: string): number[] {
        const words = this.cleanText(text);
        const sequence = words.map(word => this.vocabulary.get(word) || 0);

        // Pad or truncate
        if (sequence.length > MAX_LEN) {
            return sequence.slice(0, MAX_LEN);
        }
        while (sequence.length < MAX_LEN) {
            sequence.push(0);
        }
        return sequence;
    }

    async init() {
        if (this.model || this.isTraining) return;

        try {
            this.model = await tf.loadLayersModel('indexeddb://spam-guard-model') as tf.Sequential;
            this.model.compile({
                optimizer: tf.train.adam(0.01),
                loss: 'binaryCrossentropy',
                metrics: ['accuracy']
            });
            console.log('Model successfully loaded from IndexedDB');
        } catch (e) {
            console.log('No saved model found in IndexedDB. Training a new model now...');
            await this.train();
            if (this.model) {
                await this.model.save('indexeddb://spam-guard-model');
                console.log('Model successfully saved to IndexedDB');
            }
        }
    }

    async train() {
        if (this.isTraining) return;
        this.isTraining = true;

        // Prepare data
        const xs = tf.tensor2d(
            SPAM_dataset.map(item => this.textToSequence(item.text))
        );
        const ys = tf.tensor2d(
            SPAM_dataset.map(item => [item.label])
        );

        // Define model
        this.model = tf.sequential();
        this.model.add(tf.layers.embedding({
            inputDim: VOCAB_SIZE + 1,
            outputDim: 16,
            inputLength: MAX_LEN
        }));
        this.model.add(tf.layers.flatten());
        this.model.add(tf.layers.dense({ units: 16, activation: 'relu' }));
        this.model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

        this.model.compile({
            optimizer: tf.train.adam(0.01),
            loss: 'binaryCrossentropy',
            metrics: ['accuracy']
        });

        // Train
        await this.model.fit(xs, ys, {
            epochs: 20,
            shuffle: true,
            callbacks: {
                onEpochEnd: (epoch, logs) => {
                    console.log(`Epoch ${epoch}: loss = ${logs?.loss.toFixed(4)}, acc = ${logs?.acc.toFixed(4)}`);
                }
            }
        });

        xs.dispose();
        ys.dispose();
        this.isTraining = false;
        console.log('Model training complete');
    }

    async predict(text: string): Promise<{ isSpam: boolean; confidence: number }> {
        if (!this.model) {
            await this.init();
        }

        if (!this.model) throw new Error("Model failed to initialize");

        const sequence = this.textToSequence(text);
        const input = tf.tensor2d([sequence]);

        const prediction = this.model.predict(input) as tf.Tensor;
        const score = (await prediction.data())[0];

        input.dispose();
        prediction.dispose();

        return {
            isSpam: score > 0.5,
            confidence: score
        };
    }
}

export const spamModelService = new SpamModel();
