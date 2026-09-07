import * as tf from '@tensorflow/tfjs';
import { FRAUD_DATASET } from './fraud-dataset';

// Constants
const VOCAB_SIZE = 600;
const MAX_LEN = 30;

export class FraudModel {
  private model: tf.Sequential | null = null;
  private vocabulary: Map<string, number> = new Map();
  private isTraining = false;

  constructor() {
    this.buildVocabulary();
  }

  private cleanText(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^\w\s$]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length > 2);
  }

  private buildVocabulary() {
    const wordCounts = new Map<string, number>();

    FRAUD_DATASET.forEach((item) => {
      const words = this.cleanText(item.text);
      words.forEach((word) => {
        wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
      });
    });

    const sortedWords = Array.from(wordCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, VOCAB_SIZE);

    sortedWords.forEach((item, index) => {
      this.vocabulary.set(item[0], index + 1);
    });
  }

  private textToSequence(text: string): number[] {
    const words = this.cleanText(text);
    const sequence = words.map((word) => this.vocabulary.get(word) || 0);

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
      this.model = (await tf.loadLayersModel('indexeddb://fraud-guard-model')) as tf.Sequential;
      this.model.compile({
        optimizer: tf.train.adam(0.01),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
      });
      console.log('Fraud neural model loaded from IndexedDB cache');
    } catch (e) {
      console.log('Training local fraud neural model in browser memory...');
      await this.train();
      if (this.model) {
        try {
          await this.model.save('indexeddb://fraud-guard-model');
          console.log('Fraud neural model weights cached to IndexedDB');
        } catch (saveErr) {
          console.warn('Could not persist model to IndexedDB', saveErr);
        }
      }
    }
  }

  async train() {
    if (this.isTraining) return;
    this.isTraining = true;

    const xs = tf.tensor2d(
      FRAUD_DATASET.map((item) => this.textToSequence(item.text))
    );
    const ys = tf.tensor2d(
      FRAUD_DATASET.map((item) => [item.label])
    );

    this.model = tf.sequential();
    this.model.add(
      tf.layers.embedding({
        inputDim: VOCAB_SIZE + 1,
        outputDim: 24,
        inputLength: MAX_LEN
      })
    );
    this.model.add(tf.layers.flatten());
    this.model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
    this.model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

    this.model.compile({
      optimizer: tf.train.adam(0.01),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });

    await this.model.fit(xs, ys, {
      epochs: 25,
      shuffle: true
    });

    xs.dispose();
    ys.dispose();
    this.isTraining = false;
    console.log('Fraud neural model training complete');
  }

  async predict(text: string): Promise<{ isFraud: boolean; confidence: number }> {
    if (!this.model) {
      await this.init();
    }

    if (!this.model) throw new Error('Fraud model failed to initialize');

    const sequence = this.textToSequence(text);
    const input = tf.tensor2d([sequence]);

    const prediction = this.model.predict(input) as tf.Tensor;
    const score = (await prediction.data())[0];

    input.dispose();
    prediction.dispose();

    return {
      isFraud: score > 0.5,
      confidence: score
    };
  }
}

export const fraudModelService = new FraudModel();
