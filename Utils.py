import numpy as np 
import pandas as pd
from sklearn.preprocessing import MinMaxScaler,StandardScaler

class FlowReader:
    every_cols = ['Flow ID', ' Source IP', ' Source Port', ' Destination IP',
       ' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration',
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
       'Bwd Packet Length Max', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s',
       ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
       ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
       ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
       ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags',
       ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
       ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s',
       ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
       ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
       'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
       ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
       ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio',
       ' Average Packet Size', ' Avg Fwd Segment Size',
       ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
       ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
       ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
       ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
       'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
       ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean',
       ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std',
       ' Idle Max', ' Idle Min', ' Label'
    ]

    cols = [' Source IP', ' Source Port', ' Destination IP',
       ' Destination Port', ' Timestamp', 
       ' Total Fwd Packets', ' Total Backward Packets',
       'Total Length of Fwd Packets', ' Total Length of Bwd Packets',' Flow Duration',' Label']
    
    @staticmethod
    def read_csv(files):
        df = pd.DataFrame(
            columns = FlowReader.cols,
        )

        for file in files:
            df = pd.concat([
                df, pd.read_csv(file,encoding='utf-8')
            ])
        
        df = df[FlowReader.cols]

        return df


##########################################################################################


class FlowProfiler:
  # flow dataSet을 프로파일링합니다. scaler는 적용하지 않습니다. 
  
  UNIT_TIME = 30
  INNER_IP = {
    # 내부 IP를 기준으로 분류함 https://www.unb.ca/cic/datasets/ids-2017.html
      '192.168.10.50',
      '205.174.165.68',
      '192.168.10.51',
      '205.174.165.66',
      '192.168.10.19',
      '192.168.10.17',
      '192.168.10.16',
      '192.168.10.12',
      '192.168.10.9',
      '192.168.10.5',
      '192.168.10.8',
      '192.168.10.14',
      '192.168.10.15',
      '192.168.10.25',
      '205.174.165.80',
      '172.16.0.1',
      '192.168.10.3',
  }    

  @staticmethod
  def preprocessing(df, mode="default"):
      # IP 프로파일링
      df = df.apply(FlowProfiler.ip_preprocessing, axis=1)
      df = pd.DataFrame(df.tolist())      
      
      # 시간 프로파일링
      df = FlowProfiler.time_preprocessing(df, mode=mode)
      
      return df
      
  @staticmethod
  def ip_preprocessing(df):
      # 외부 - 내부 IP를 먼저 구분한다
      isSrcInner = False
      isDstInner = False
      if df[' Source IP'] in FlowProfiler.INNER_IP:
          isSrcInner = True
      if df[' Destination IP'] in FlowProfiler.INNER_IP:
          isDstInner = True
      
      isSrcOuter = True
      
      if isSrcInner and not isDstInner:
          # 출발지 IP는 내부 IP이고 도착지 IP가 외부아이피인 경우
            # 다른 상황들
            # 1. 출발지 IP가 외부 IP, 도착지 IP가 내부 IP인 경우 -> 정상작동
            # 2. 둘다 내부 IP인 경우 -> 출발지 IP를 외부아이피로 간주 -> 정상작동
            
          isSrcOuter = False  
      
      col_names = [
          '{} ip',
          '{} port',
          '{} packets',
          '{} bytes',
      ]
      src_keys = [
          ' Source IP', ' Source Port', ' Total Fwd Packets', 'Total Length of Fwd Packets',
      ]
      dst_keys = [
          ' Destination IP', ' Destination Port', ' Total Backward Packets',' Total Length of Bwd Packets',
      ]

      ret = {}
      if isSrcOuter:
          for i in range(4):
              ret[col_names[i].format('outer')] = df[src_keys[i]]
              ret[col_names[i].format('inner')] = df[dst_keys[i]]
      else:
          for i in range(4):
              ret[col_names[i].format('outer')] = df[dst_keys[i]]
              ret[col_names[i].format('inner')] = df[src_keys[i]]

    #   ret['Timestamp'] = df[' Timestamp']
      times = df[' Timestamp']
      times = times.split()[1]
      times = list(map(int, times.split(':')))
      ret['Timestamp'] = times[1] + times[0] * 60
      ret['Time Group'] = ret['Timestamp'] // FlowProfiler.UNIT_TIME 
      
      ret['Flow Duration'] = df[' Flow Duration']
      
      ret['pst'] = '{}:{}:{}:{}'.format(
        ret['inner packets'],
        ret['outer packets'],
        ret['inner bytes'],
        ret['inner bytes'],
      )

      ret['Label'] = df[' Label']
      
      return ret

  @staticmethod
  def time_preprocessing(df, mode):
    new_df = []
    time_groups = df['Time Group'].unique()
    for time_group in time_groups:
        time_group_df = df[df['Time Group'] == time_group]
        # print(time_group, time_group_df.size)
        outer_ips = time_group_df['outer ip'].unique()
        for outer_ip in outer_ips:
            group = time_group_df[time_group_df['outer ip'] == outer_ip]

            inner_port = group['inner port'].value_counts()
            outer_port = group['outer port'].value_counts()

            tmp = {
                'Key_IP' : outer_ip, 
                'Key_inner_port' : inner_port.keys()[0],
                'Key_outer_port' : outer_port.keys()[0],
                
                'Inner_port_freq' : inner_port.values[0]/ inner_port.sum(),
                'Outer_port_freq' : outer_port.values[0]/ outer_port.sum(),
                'Pst_per_flows' : group['pst'].unique().shape[0] / group.shape[0],
                
                'Card_inner_ip' : group['inner ip'].unique().shape[0],
                'Card_inner_port' : group['inner port'].unique().shape[0],
                'Card_outer_port' : group['outer port'].unique().shape[0],
                
                'Sum_inner_pkts' : group['inner packets'].sum(),
                'Avg_inner_pkts' : group['inner packets'].mean(),
                'Std_inner_pkts' : group['inner packets'].std(),
                
                'Sum_inner_bytes' : group['inner bytes'].sum(),
                'Avg_inner_bytes' : group['inner bytes'].mean(),
                'Std_inner_bytes' : group['inner bytes'].std(),
                
                'Sum_outer_pkts' : group['outer packets'].sum(),
                'Avg_outer_pkts' : group['outer packets'].mean(),
                'Std_outer_pkts' : group['outer packets'].std(),
                
                'Sum_outer_bytes' : group['outer bytes'].sum(),
                'Avg_outer_bytes' : group['outer bytes'].mean(),
                'Std_outer_bytes' : group['outer bytes'].std(),
                
                'Sum_dur' : group['Flow Duration'].sum(),
                'Avg_dur' : group['Flow Duration'].mean(),
                'Std_dur' : group['Flow Duration'].std(),
                
                'Label' : group['Label'].unique()
            } 
            
            if mode == "expand":
                tmp = {
                    **tmp,
                    'Min_inner_pkts' : group['inner packets'].min(),
                    'Max_inner_pkts' : group['inner packets'].max(),
                    'Median_inner_pkts' : group['inner packets'].median(),
                    
                    'Min_inner_bytes' : group['inner bytes'].min(),
                    'Max_inner_bytes' : group['inner bytes'].max(),
                    'Median_inner_bytes' : group['inner bytes'].median(),
                    
                    'Min_outer_pkts' : group['outer packets'].min(),
                    'Max_outer_pkts' : group['outer packets'].max(),
                    'Median_outer_pkts' : group['outer packets'].median(),
                    
                    'Min_outer_bytes' : group['outer bytes'].min(),
                    'Max_outer_bytes' : group['outer bytes'].max(),
                    'Median_outer_bytes' : group['outer bytes'].median(),
                    
                    'Min_dur' : group['Flow Duration'].min(),
                    'Max_dur' : group['Flow Duration'].max(),
                    'Median_dur' : group['Flow Duration'].median(),
                }

            new_df.append(tmp)

    df = pd.DataFrame(new_df)
    df = df.fillna(0) # 표준편차에서만 null값이 생성됨
    
    return df

##########################################################################################

class FlowPreProcessor:
  # 데이터 프레임을 전처리하는 객체
    def __init__(self, mode="minmax"):
        self.ip_encoder = CdfEncoder()
        self.inner_port_encoder = CdfEncoder()
        self.outer_port_encoder = CdfEncoder()
        
        self.minmaxScaler = None
        self.pdfScaler = None
        
        if mode == "concat":
            self.minmaxScaler = MinMaxScaler()
            self.pdfScaler = PdfScaler()
        elif mode == "pdf":
            self.pdfScaler = PdfScaler()
        else:   # MinMax
            self.minmaxScaler = MinMaxScaler()

    def fit(self, df):
        trainX = df.drop(columns = ['Key_IP', 'Key_inner_port', 'Key_outer_port', 'Label'])

        self.ip_encoder.fit(
            df['Key_IP'].value_counts()
        )

        self.inner_port_encoder.fit(
            df['Key_inner_port'].value_counts()
        )
        
        self.outer_port_encoder.fit(
            df['Key_outer_port'].value_counts()
        )
        
        if self.minmaxScaler is not None:        
            self.minmaxScaler.fit(trainX)
        if self.pdfScaler is not None:
            self.pdfScaler.fit(trainX.values)
    
    def transform(self, df):
        X = df.drop(columns = ['Key_IP', 'Key_inner_port', 'Key_outer_port', 'Label'])

        X_ip = self.ip_encoder.transform(
            df['Key_IP'].values
        )

        X_inner_port = self.inner_port_encoder.transform(
            df['Key_inner_port'].values
        )
        
        X_outer_port = self.outer_port_encoder.transform(
            df['Key_outer_port'].values
        )

        ret = np.array([
            X_ip,
            X_inner_port,
            X_outer_port
        ]).T
        
        if self.minmaxScaler is not None:   
            X_minmax = self.minmaxScaler.transform(X)
            ret = np.concatenate([
                ret,
                X_minmax,
            ],axis=1,dtype='float32')

        if self.pdfScaler is not None:
            X_pdf = self.pdfScaler.transform(X.values)     
            ret = np.concatenate([
                ret,
                X_pdf,
            ],axis=1,dtype='float32')
            
        return ret

    def fit_transform(self, df):
        self.fit(df)
        return self.transform(df)

class CdfEncoder:
    # 범주형 데이터의 CDF 인코딩 객체
    def __init__(self):
        pass

    def fit(self, x):
        pdf = x / x.sum()
        cdf = np.cumsum(pdf.unique()[::-1])
        tmp_table = {}
        for idx, val in enumerate(x.unique()[::-1]): 
            tmp_table[val] = cdf[idx]
        self.cdf_table = {}
        for key in x.keys():
            self.cdf_table[key] = tmp_table[x[key]]
        self.default_value = cdf.min()

    def transform(self, x):
        ret = []
        for i in x:
            if i in self.cdf_table:
                ret.append(self.cdf_table[i])
            else:
                ret.append(self.default_value)
        return ret

class PdfCalculator:
    def __init__(self, x):
        height, self.bins = np.histogram(x, bins=256)
        self.pdf = height / np.size(height)
        self.scaler = MinMaxScaler()

        self.pdf = np.append(self.pdf, 0.0) # 최대값을 넘어서면 
        self.pdf = np.append(0.0, self.pdf) # 최소값을 넘어서면 

        self.pdf = self.scaler.fit_transform(self.pdf.reshape(-1,1))

    def cal(self, x):
        y = np.digitize(x, self.bins,)
        ret = self.pdf[y]
        ret = ret.reshape(-1)
        return ret

class PdfScaler:
    def __init__(self):
        pass
    
    def transform(self, x):
        ret = []
        for idx in range(x.shape[1]):
            ret.append(
                self.calculator[idx].cal(x[:,idx])
            )
        return np.array(ret).T

    def fit(self, x):
        self.calculator = []
        for idx in range(x.shape[1]):
            self.calculator.append(PdfCalculator(x[:,idx]))

    def fit_transform(self, x):
        self.fit(x)
        return self.transform(x)

class PdfCalculator:
    def __init__(self, x):
        height, self.bins = np.histogram(x, bins=256)
        self.pdf = height / np.size(height)
        self.scaler = MinMaxScaler()

        self.pdf = np.append(self.pdf, 0.0) # 최대값을 넘어서면 
        self.pdf = np.append(0.0, self.pdf) # 최소값을 넘어서면 

        self.pdf = self.scaler.fit_transform(self.pdf.reshape(-1,1))

    def cal(self, x):
        y = np.digitize(x, self.bins,)
        ret = self.pdf[y]
        ret = ret.reshape(-1)
        return ret

class PdfScaler:
    def __init__(self):
        pass
    
    def transform(self, x):
        ret = []
        for idx in range(x.shape[1]):
            ret.append(
                self.calculator[idx].cal(x[:,idx])
            )
        return np.array(ret).T

    def fit(self, x):
        self.calculator = []
        for idx in range(x.shape[1]):
            self.calculator.append(PdfCalculator(x[:,idx]))

    def fit_transform(self, x):
        self.fit(x)
        return self.transform(x)

