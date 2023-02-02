# ipod_model

https://www.unb.ca/cic/datasets/ids-2017.html 의 데이터를 사용하였습니다. (Thursday 데이터는 읽기가 되지 않아 테스트셋에 포함하지 못했습니다.)

실행환경은 colab에 로컬런타임을 연결하여 사용하였습니다.

# Variation
## 테스트한 기법들
### Pdf 
범주형 데이터 전처리 -> CDF 사용

수치형 데이터 전처리할 때도 minmax 스케일러 pdf 함수를 사용할 수 있다고 생각하여 적용해보았습니다. 

### concat
minmax scaler를 사용한 피처와 pdf scaler를 사용한 피처를 동시에 사용하는 모델입니다. 


# test
아래의 모델들로 테스트를 진행하였습니다. 
|  | minmax scaler | pdf scaler | concat scaler|
| ---|---|---|---|
|기본| **ipod_model** | **ipod_model_pdf** | **ipod_model_concat**|
|expand | **ipod_model_expand** | **ipod_model_expand_pdf** | **ipod_model_expand_concat** |

### 하이퍼 파라미터 
모든 모델이 동일한 하이퍼 파라미터로 작동하엿습니다

전처리 과정에서 단위시간을 5분으로 하여 통계를 추출하였습니다. 



### auroc 점수
| 순위 | 모델명 | 화요일 | 수요일 | 금요일 | 금요일(BOT) | 전체 | 
| ---|---|---|---|---|---|---|
| 1 | ipod_model | 0.989 | 0.990 | 0.991 | 0.980 | 0.987 | 
| 2 | ipod_model_expand | 0.988 | 0.987 | 0.990 | 0.962 | 0.979 | 
| 3 | ipod_model_concat | 0.982 | 0.978 | 0.977 | 0.960 | 0.973 | 
| 4 | ipod_model_expand_concat | 0.989 | 0.971 | 0.968 | 0.943 | 0.968 | 
| 5 | ipod_model_expand_pdf | 0.992 | 0.970 |0.962 | 0.943 | 0.965 | 
| 6 | ipod_model_pdf | 0.920 | 0.960 | 0.944 | 0.950 | 0.943 | 

pdf 인코딩 및 feature 추가로는 유의미한 성능향상을 기대하기 어렵다는 것을 확인할 수 있습니다. 
