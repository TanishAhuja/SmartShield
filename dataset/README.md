# Dataset

SmartShield is trained on the **UNSW-NB15** dataset, which is not redistributed
in this repo because of its size (~45 MB of CSVs) and licensing.

## Download

Grab `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` from either:

- Official UNSW page: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Kaggle mirror: https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15

Place both files directly inside this `dataset/` directory so the paths look
like:

```
dataset/UNSW_NB15_training-set.csv
dataset/UNSW_NB15_testing-set.csv
```

Then run `python train_model.py` from the project root to generate the model
artifacts.
