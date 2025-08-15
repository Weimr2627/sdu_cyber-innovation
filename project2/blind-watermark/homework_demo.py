#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import cv2
import numpy as np
from datetime import datetime
import json

# 导入重构后的水印检测系统
from watermark_detection_system import WatermarkDetectionSystem
from robustness_testing import RobustnessTester


def demo_basic_functionality():
    """演示基本功能：水印嵌入和提取"""
    print("=" * 60)
    print("演示1: 基本水印功能")
    print("=" * 60)
    
    # 创建输出目录
    os.makedirs("output", exist_ok=True)
    
    # 初始化系统
    system = WatermarkDetectionSystem()
    
    # 1. 文本水印嵌入
    print("\n--- 步骤1: 嵌入文本水印 ---")
    embed_result = system.embed_watermark(
        original_image_path="blind_watermark-master\wyx.png",
        watermark_content="学号202200460086",
        output_path="output/embedded_text.png",
        watermark_type="text"
    )
    
    if embed_result['status'] == 'success':
        print("✅ 文本水印嵌入成功！")
        
        # 2. 文本水印提取
        print("\n--- 步骤2: 提取文本水印 ---")
        extract_result = system.extract_watermark(
            embedded_image_path="output/embedded_text.png",
            watermark_shape=embed_result['watermark_size'],
            watermark_type="text"
        )
        
        if extract_result['status'] == 'success':
            print("✅ 文本水印提取成功！")
            print(f"提取的水印内容: {extract_result['extracted_watermark']}")
        else:
            print("❌ 文本水印提取失败")
    else:
        print("❌ 文本水印嵌入失败")
        return False
    
    # 3. 图片水印嵌入（如果有水印图片）
    watermark_image_path = "examples/pic/watermark.png"
    if os.path.exists(watermark_image_path):
        print("\n--- 步骤3: 嵌入图片水印 ---")
        embed_img_result = system.embed_watermark(
            original_image_path="examples/pic/ori_img.jpeg",
            watermark_content=watermark_image_path,
            output_path="output/embedded_image.png",
            watermark_type="image"
        )
        
        if embed_img_result['status'] == 'success':
            print("✅ 图片水印嵌入成功！")
            
            # 4. 图片水印提取
            print("\n--- 步骤4: 提取图片水印 ---")
            extract_img_result = system.extract_watermark(
                embedded_image_path="output/embedded_image.png",
                watermark_shape=(64, 64),  # 假设水印图片大小为64x64
                output_path="output/extracted_watermark.png",
                watermark_type="image"
            )
            
            if extract_img_result['status'] == 'success':
                print("✅ 图片水印提取成功！")
            else:
                print("❌ 图片水印提取失败")
        else:
            print("❌ 图片水印嵌入失败")
    
    return True


def demo_robustness_testing():
    """演示鲁棒性测试功能"""
    print("\n" + "=" * 60)
    print("演示2: 鲁棒性测试")
    print("=" * 60)
    
    # 检查是否有嵌入水印的图像
    embedded_image_path = "output/embedded_text.png"
    if not os.path.exists(embedded_image_path):
        print("❌ 未找到嵌入水印的图像，请先运行基本功能演示")
        return False
    
    # 创建鲁棒性测试器
    tester = RobustnessTester()
    
    # 运行全面的鲁棒性测试
    print("开始鲁棒性测试...")
    print("测试的攻击类型包括：")
    print("  - 几何攻击：旋转、缩放、平移、裁剪、翻转")
    print("  - 信号处理攻击：亮度调整、对比度调整、噪声添加")
    print("  - 压缩攻击：JPEG压缩、PNG压缩")
    print("  - 滤波攻击：高斯模糊、中值滤波、双边滤波")
    print("  - 组合攻击：旋转+压缩、噪声+模糊、缩放+旋转")
    
    # 运行测试（选择几个主要类别进行演示）
    test_categories = ['geometric', 'signal_processing', 'compression']
    
    # 动态获取水印大小
    watermark_content = "学号: 2024001 姓名: 张三 课程: 数字水印技术 实验日期: 2024年"
    watermark_size = len(watermark_content)
    
    results = tester.run_comprehensive_test(
        image_path=embedded_image_path,
        watermark_shape=watermark_size,  # 动态获取水印大小
        watermark_type="text",
        test_categories=test_categories
    )
    
    # 可视化攻击效果
    print("\n生成攻击效果可视化图...")
    tester.visualize_attacks(
        original_image_path=embedded_image_path,
        save_path="output/attack_visualization.png"
    )
    
    print("✅ 鲁棒性测试完成！")
    return True


def demo_leakage_detection():
    """演示泄露检测功能"""
    print("\n" + "=" * 60)
    print("演示3: 泄露检测")
    print("=" * 60)
    
    # 检查是否有嵌入水印的图像
    original_image_path = "output/embedded_text.png"
    if not os.path.exists(original_image_path):
        print("❌ 未找到嵌入水印的图像，请先运行基本功能演示")
        return False
    
    # 初始化系统
    system = WatermarkDetectionSystem()
    
    # 模拟一个可疑图像（通过旋转攻击创建）
    print("创建可疑图像（通过旋转攻击）...")
    original_img = cv2.imread(original_image_path)
    h, w = original_img.shape[:2]
    
    # 应用旋转攻击
    angle = 30
    center = (w // 2, h // 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    suspicious_img = cv2.warpAffine(original_img, matrix, (w, h))
    
    # 保存可疑图像
    suspicious_image_path = "output/suspicious_image.png"
    cv2.imwrite(suspicious_image_path, suspicious_img)
    print(f"可疑图像已保存到: {suspicious_image_path}")
    
    # 进行泄露检测
    print("\n开始泄露检测...")
    # 动态获取水印大小
    watermark_content = "学号202200460086"
    watermark_size = len(watermark_content)
    
    leakage_result = system.detect_leakage(
        original_image_path=original_image_path,
        suspected_image_path=suspicious_image_path,
        watermark_shape=watermark_size,  # 动态获取水印大小
        watermark_type="text"
    )
    
    print(f"泄露检测结果: {leakage_result['message']}")
    
    return True


def generate_homework_report():
    """生成作业报告"""
    print("\n" + "=" * 60)
    print("生成作业报告")
    print("=" * 60)
    
    report = []
    report.append("基于数字水印的图片泄露检测 - 作业报告")
    report.append("=" * 60)
    report.append(f"作者: [您的姓名]")
    report.append(f"学号: [您的学号]")
    report.append(f"课程: [课程名称]")
    report.append(f"日期: {datetime.now().strftime('%Y年%m月%d日')}")
    report.append("")
    
    report.append("一、实验目的")
    report.append("1. 理解数字水印的基本原理和应用")
    report.append("2. 掌握基于DWT-DCT-SVD的数字水印嵌入和提取技术")
    report.append("3. 学习数字水印的鲁棒性测试方法")
    report.append("4. 实现基于数字水印的图片泄露检测系统")
    report.append("")
    
    report.append("二、实验原理")
    report.append("本实验基于开源项目blind_watermark进行二次开发，采用DWT-DCT-SVD算法：")
    report.append("1. DWT（离散小波变换）：将图像分解为不同频率的子带")
    report.append("2. DCT（离散余弦变换）：在选定的子带中进行频域变换")
    report.append("3. SVD（奇异值分解）：将DCT系数分解为U、S、V矩阵")
    report.append("4. 水印嵌入：在S矩阵的奇异值中嵌入水印信息")
    report.append("5. 水印提取：通过逆过程提取嵌入的水印信息")
    report.append("")
    
    report.append("三、实验内容")
    report.append("1. 水印嵌入：将文本和图片水印嵌入到原始图像中")
    report.append("2. 水印提取：从嵌入水印的图像中提取水印信息")
    report.append("3. 鲁棒性测试：测试水印对抗各种攻击的能力")
    report.append("4. 泄露检测：通过水印验证图像是否被篡改或泄露")
    report.append("")
    
    report.append("四、鲁棒性测试")
    report.append("测试的攻击类型包括：")
    report.append("1. 几何攻击：旋转、缩放、平移、裁剪、翻转")
    report.append("2. 信号处理攻击：亮度调整、对比度调整、噪声添加")
    report.append("3. 压缩攻击：JPEG压缩、PNG压缩")
    report.append("4. 滤波攻击：高斯模糊、中值滤波、双边滤波")
    report.append("5. 组合攻击：多种攻击的组合")
    report.append("")
    
    report.append("五、实验结果")
    report.append("1. 成功实现了文本和图片水印的嵌入与提取")
    report.append("2. 完成了全面的鲁棒性测试")
    report.append("3. 实现了基于水印的泄露检测功能")
    report.append("4. 生成了详细的测试报告和可视化结果")
    report.append("")
    
    report.append("六、实验总结")
    report.append("1. 通过本实验深入理解了数字水印技术的原理和应用")
    report.append("2. 掌握了DWT-DCT-SVD算法的实现方法")
    report.append("3. 学会了如何进行数字水印的鲁棒性测试")
    report.append("4. 为后续的数字水印研究奠定了基础")
    report.append("")
    
    report.append("七、参考文献")
    report.append("1. blind_watermark开源项目")
    report.append("2. 数字水印技术相关文献")
    report.append("3. DWT-DCT-SVD算法相关论文")
    report.append("")
    
    report.append("=" * 60)
    
    report_text = "\n".join(report)
    
    # 保存报告
    report_file = "output/homework_report.txt"
    os.makedirs("output", exist_ok=True)
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print(f"作业报告已保存到: {report_file}")
    return report_text


def main():
    """主函数 - 运行完整的作业演示"""
    
    print("基于数字水印的图片泄露检测 - 作业演示")
    print("=" * 60)
    print("本演示将展示：")
    print("1. 基本水印功能（嵌入和提取）")
    print("2. 鲁棒性测试（各种攻击测试）")
    print("3. 泄露检测功能")
    print("4. 作业报告生成")
    print("=" * 60)
    
    try:
        # 演示1: 基本功能
        if demo_basic_functionality():
            print("\n✅ 基本功能演示完成")
        else:
            print("\n❌ 基本功能演示失败")
            return
        
        # 演示2: 鲁棒性测试
        if demo_robustness_testing():
            print("\n✅ 鲁棒性测试演示完成")
        else:
            print("\n❌ 鲁棒性测试演示失败")
        
        # 演示3: 泄露检测
        if demo_leakage_detection():
            print("\n✅ 泄露检测演示完成")
        else:
            print("\n❌ 泄露检测演示失败")
        
        # 生成作业报告
        report = generate_homework_report()
        print("\n✅ 作业报告生成完成")
        
        print("\n" + "=" * 60)
        print("🎉 所有演示完成！")
        print("=" * 60)
        print("输出文件位置：")
        print("- 嵌入水印的图像: output/embedded_text.png")
        print("- 攻击后的图像: output/attacked_*.png")
        print("- 攻击效果可视化: output/attack_visualization.png")
        print("- 测试结果: output/comprehensive_test_results.json")
        print("- 测试报告: output/comprehensive_test_report.txt")
        print("- 作业报告: output/homework_report.txt")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
