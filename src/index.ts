import express, { Express, Request, Response , Application } from 'express';
import dotenv from 'dotenv';
import { buildTx, signTx } from './services/build-tx';
import { Seed } from './utils';
import cors from 'cors';
import { createScript } from './services/create-script';

//For env File 
dotenv.config();

const app: Application = express();
const port = process.env.PORT || 8000;

app.use(express.json());
app.use(cors())

app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to Express & TypeScript Server!!!');
});

const amount = Seed.cborEncodeAmount(5000000);
console.log('Amount:', amount);

app.post('/buildTx', async (req: Request, res: Response) => {
  const build = await buildTx(req.body);
  res.json(build);
});

app.post('/signTx', (req: Request, res: Response) => {
  const tx = signTx(req.body);
  res.json({ tx });

})

app.post('/createScript', async (req: Request, res: Response) => {
  const script = await createScript(req.body);
  res.json(script);

})

app.listen(port, () => {
  console.log(`Server is Fire at http://localhost:${port}`);
});