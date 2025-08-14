## 项目架构

```
项目blind_watermark/
├── watermark_detection_system.py    # 主水印检测系统
├── robustness_testing.py            # 鲁棒性测试模块
├── homework_demo.py                 # 作业演示主程序
├── README.md                        # 说明文件
└── output/                          # 输出目录
```

## 代码功能介绍

#### 步骤1：基本水印功能
```python

# 创建系统
system = WatermarkDetectionSystem()

# 嵌入文本水印
embed_result = system.embed_watermark(
    original_image_path="blindwatermark/wyx.png",
    watermark_content="学号202200460086",
    output_path="output/embedded_text.png",
    watermark_type="text"
)

# 提取水印
extract_result = system.extract_watermark(
    embedded_image_path="output/embedded_text.png",
    watermark_shape=embed_result['watermark_size'],
    watermark_type="text"
)
```

#### 步骤2：鲁棒性测试
```python
from robustness_testing import RobustnessTester

# 创建测试器
tester = RobustnessTester()

# 运行测试
results = tester.run_comprehensive_test(
    image_path="output/embedded_text.png",
    watermark_shape=111,
    watermark_type="text",
    test_categories=['geometric', 'signal_processing']
)

# 可视化攻击效果
tester.visualize_attacks(
    original_image_path="output/embedded_text.png",
    save_path="output/attack_visualization.png"
)
```

#### 步骤3：泄露检测
```python
# 检测泄露
leakage_result = system.detect_leakage(
    original_image_path="output/embedded_text.png",
    suspected_image_path="output/suspicious_image.png",
    watermark_shape=111,
    watermark_type="text"
)
```

### 各种攻击后的效果

|攻击方式|攻击后的图片|提取的水印|
|--|--|--|
|上下反转|![旋转攻击](output\attacked_geometric_flipping.png)|'学号202200460086'|
|旋转攻击45度|![旋转攻击](output\attacked_geometric_rotation.png)|'学号202200460086'|
|随机截图|![截屏攻击](output\attacked_geometric_cropping.png)|'学号202200460086'|
|遮挡| ![遮挡攻击](output\attacked_geometric_scaling.png) |'学号202200460086'|
|裁剪攻击|![纵向裁剪攻击](output\attacked_geometric_cropping.png)|'学号202200460086！'|
|缩放攻击|![缩放攻击](output\attacked_geometric_translation.png)|'学号202200460086'|
|椒盐攻击|![椒盐攻击](output\attacked_signal_processing_histogram_equalization.png)|'学号202200460086'|
|对比度攻击|![亮度(对比度)攻击](output\attacked_signal_processing_noise.png)|'学号202200460086'|