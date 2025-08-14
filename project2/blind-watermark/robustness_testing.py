#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
鲁棒性测试模块
专门用于测试数字水印对抗各种攻击的能力

包含的攻击类型：
1. 几何攻击：旋转、缩放、平移、裁剪
2. 信号处理攻击：亮度调整、对比度调整、噪声添加
3. 压缩攻击：JPEG压缩、PNG压缩
4. 滤波攻击：高斯模糊、中值滤波
5. 组合攻击：多种攻击的组合
"""

import cv2
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import os
from datetime import datetime
import json
from typing import Dict, List, Tuple, Any, Union

class RobustnessTester:
    """鲁棒性测试器"""
    
    def __init__(self, output_dir: str = "output"):
        """
        初始化鲁棒性测试器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # 定义所有可用的攻击类型
        self.available_attacks = {
            'geometric': ['rotation', 'scaling', 'translation', 'cropping', 'flipping'],
            'signal_processing': ['brightness', 'contrast', 'noise', 'histogram_equalization'],
            'compression': ['jpeg_compression', 'png_compression'],
            'filtering': ['gaussian_blur', 'median_filter', 'bilateral_filter'],
            'combined': ['rotation_compression', 'noise_blur', 'scaling_rotation']
        }
        
        # 测试结果存储
        self.test_results = {}
        self.attack_images = {}
        
        print("鲁棒性测试器初始化完成")
        print(f"支持的攻击类型: {len(self.available_attacks)} 大类")
        for category, attacks in self.available_attacks.items():
            print(f"  {category}: {', '.join(attacks)}")
    
    def run_comprehensive_test(self, 
                              image_path: str, 
                              watermark_shape: Union[int, Tuple[int, int]],
                              watermark_type: str = 'text',
                              test_categories: List[str] = None) -> Dict[str, Any]:
        """
        运行全面的鲁棒性测试
        
        Args:
            image_path: 嵌入水印的图像路径
            watermark_shape: 水印形状
            watermark_type: 水印类型
            test_categories: 要测试的类别，如果为None则测试所有类别
            
        Returns:
            测试结果字典
        """
        if test_categories is None:
            test_categories = list(self.available_attacks.keys())
        
        print(f"\n开始全面鲁棒性测试...")
        print(f"测试图像: {image_path}")
        print(f"水印形状: {watermark_shape}")
        print(f"水印类型: {watermark_type}")
        print(f"测试类别: {', '.join(test_categories)}")
        
        # 读取原始图像
        original_image = cv2.imread(image_path)
        if original_image is None:
            raise ValueError(f"无法读取图像: {image_path}")
        
        # 为每个类别运行测试
        for category in test_categories:
            if category in self.available_attacks:
                print(f"\n--- 测试 {category} 类别 ---")
                self._test_category(
                    category, 
                    original_image, 
                    watermark_shape, 
                    watermark_type
                )
        
        # 保存测试结果
        self._save_comprehensive_results()
        
        # 生成测试报告
        self._generate_comprehensive_report()
        
        return self.test_results
    
    def _test_category(self, 
                      category: str, 
                      original_image: np.ndarray, 
                      watermark_shape: Union[int, Tuple[int, int]],
                      watermark_type: str):
        """测试特定类别的攻击"""
        category_results = {}
        
        for attack_type in self.available_attacks[category]:
            print(f"  测试 {attack_type} 攻击...")
            
            try:
                # 应用攻击
                attacked_image, attack_params = self._apply_attack(
                    original_image, attack_type
                )
                
                # 保存攻击后的图像
                attack_output_path = os.path.join(
                    self.output_dir, f"attacked_{category}_{attack_type}.png"
                )
                cv2.imwrite(attack_output_path, attacked_image)
                
                # 记录攻击图像
                self.attack_images[f"{category}_{attack_type}"] = {
                    'path': attack_output_path,
                    'params': attack_params
                }
                
                # 记录测试结果
                category_results[attack_type] = {
                    'attack_params': attack_params,
                    'output_path': attack_output_path,
                    'status': 'completed'
                }
                
                print(f"    ✅ {attack_type} 攻击完成")
                
            except Exception as e:
                print(f"    ❌ {attack_type} 攻击失败: {str(e)}")
                category_results[attack_type] = {
                    'status': 'error',
                    'error_message': str(e)
                }
        
        self.test_results[category] = category_results
    
    def _apply_attack(self, image: np.ndarray, attack_type: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        应用特定的攻击到图像
        
        Args:
            image: 输入图像
            attack_type: 攻击类型
            
        Returns:
            攻击后的图像和攻击参数
        """
        h, w = image.shape[:2]
        attack_params = {}
        
        if attack_type == 'rotation':
            # 旋转攻击
            angle = np.random.uniform(15, 75)  # 随机角度
            center = (w // 2, h // 2)
            matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
            attacked_image = cv2.warpAffine(image, matrix, (w, h))
            attack_params = {'angle': angle, 'center': center}
            
        elif attack_type == 'scaling':
            # 缩放攻击
            scale = np.random.uniform(0.6, 1.4)  # 随机缩放比例
            new_w, new_h = int(w * scale), int(h * scale)
            attacked_image = cv2.resize(image, (new_w, new_h))
            attacked_image = cv2.resize(attacked_image, (w, h))  # 恢复原尺寸
            attack_params = {'scale': scale}
            
        elif attack_type == 'translation':
            # 平移攻击
            tx = np.random.randint(-w//4, w//4)  # 随机平移距离
            ty = np.random.randint(-h//4, h//4)
            matrix = np.float32([[1, 0, tx], [0, 1, ty]])
            attacked_image = cv2.warpAffine(image, matrix, (w, h))
            attack_params = {'tx': tx, 'ty': ty}
            
        elif attack_type == 'cropping':
            # 裁剪攻击
            crop_ratio = np.random.uniform(0.6, 0.9)  # 随机裁剪比例
            start_x = int(w * (1 - crop_ratio) // 2)
            start_y = int(h * (1 - crop_ratio) // 2)
            end_x = start_x + int(w * crop_ratio)
            end_y = start_y + int(h * crop_ratio)
            attacked_image = image[start_y:end_y, start_x:end_x]
            attacked_image = cv2.resize(attacked_image, (w, h))  # 恢复原尺寸
            attack_params = {'crop_ratio': crop_ratio, 'start': (start_x, start_y), 'end': (end_x, end_y)}
            
        elif attack_type == 'flipping':
            # 翻转攻击
            flip_code = np.random.choice([0, 1, -1])  # 随机选择翻转方式
            attacked_image = cv2.flip(image, flip_code)
            attack_params = {'flip_code': flip_code}
            
        elif attack_type == 'brightness':
            # 亮度攻击
            brightness_factor = np.random.uniform(0.5, 2.0)  # 随机亮度因子
            attacked_image = cv2.convertScaleAbs(image, alpha=brightness_factor, beta=0)
            attack_params = {'brightness_factor': brightness_factor}
            
        elif attack_type == 'contrast':
            # 对比度攻击
            contrast_factor = np.random.uniform(0.5, 2.0)  # 随机对比度因子
            attacked_image = cv2.convertScaleAbs(image, alpha=contrast_factor, beta=0)
            attack_params = {'contrast_factor': contrast_factor}
            
        elif attack_type == 'noise':
            # 噪声攻击
            noise_type = np.random.choice(['gaussian', 'salt_pepper', 'poisson'])
            if noise_type == 'gaussian':
                noise = np.random.normal(0, np.random.uniform(10, 50), image.shape).astype(np.uint8)
                attacked_image = cv2.add(image, noise)
            elif noise_type == 'salt_pepper':
                attacked_image = image.copy()
                noise_ratio = np.random.uniform(0.01, 0.1)
                for i in range(int(h * w * noise_ratio)):
                    x = np.random.randint(0, w)
                    y = np.random.randint(0, h)
                    if np.random.random() < 0.5:
                        attacked_image[y, x] = 255
                    else:
                        attacked_image[y, x] = 0
            else:  # poisson
                noise = np.random.poisson(image.astype(float) / 255.0 * 50) * 5
                attacked_image = np.clip(image + noise, 0, 255).astype(np.uint8)
            
            attack_params = {'noise_type': noise_type}
            
        elif attack_type == 'histogram_equalization':
            # 直方图均衡化攻击
            attacked_image = image.copy()
            for i in range(3):
                attacked_image[:, :, i] = cv2.equalizeHist(image[:, :, i])
            attack_params = {'method': 'histogram_equalization'}
            
        elif attack_type == 'jpeg_compression':
            # JPEG压缩攻击
            quality = np.random.randint(10, 90)  # 随机质量
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
            _, encoded_img = cv2.imencode('.jpg', image, encode_param)
            attacked_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
            attack_params = {'quality': quality, 'format': 'jpeg'}
            
        elif attack_type == 'png_compression':
            # PNG压缩攻击
            compression_level = np.random.randint(0, 10)  # 随机压缩级别
            encode_param = [int(cv2.IMWRITE_PNG_COMPRESSION), compression_level]
            _, encoded_img = cv2.imencode('.png', image, encode_param)
            attacked_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
            attack_params = {'compression_level': compression_level, 'format': 'png'}
            
        elif attack_type == 'gaussian_blur':
            # 高斯模糊攻击
            kernel_size = np.random.choice([3, 5, 7, 9])  # 随机核大小
            sigma = np.random.uniform(0.5, 2.0)  # 随机标准差
            attacked_image = cv2.GaussianBlur(image, (kernel_size, kernel_size), sigma)
            attack_params = {'kernel_size': kernel_size, 'sigma': sigma}
            
        elif attack_type == 'median_filter':
            # 中值滤波攻击
            kernel_size = np.random.choice([3, 5, 7])  # 随机核大小
            attacked_image = cv2.medianBlur(image, kernel_size)
            attack_params = {'kernel_size': kernel_size}
            
        elif attack_type == 'bilateral_filter':
            # 双边滤波攻击
            d = np.random.choice([5, 9, 15])  # 随机直径
            sigma_color = np.random.uniform(50, 150)  # 随机颜色标准差
            sigma_space = np.random.uniform(50, 150)  # 随机空间标准差
            attacked_image = cv2.bilateralFilter(image, d, sigma_color, sigma_space)
            attack_params = {'d': d, 'sigma_color': sigma_color, 'sigma_space': sigma_space}
            
        elif attack_type == 'rotation_compression':
            # 旋转+压缩组合攻击
            # 先旋转
            angle = np.random.uniform(15, 45)
            center = (w // 2, h // 2)
            matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
            rotated = cv2.warpAffine(image, matrix, (w, h))
            # 再压缩
            quality = np.random.randint(20, 60)
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
            _, encoded_img = cv2.imencode('.jpg', rotated, encode_param)
            attacked_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
            attack_params = {'rotation_angle': angle, 'compression_quality': quality}
            
        elif attack_type == 'noise_blur':
            # 噪声+模糊组合攻击
            # 先加噪声
            noise = np.random.normal(0, 30, image.shape).astype(np.uint8)
            noisy = cv2.add(image, noise)
            # 再模糊
            attacked_image = cv2.GaussianBlur(noisy, (5, 5), 1.5)
            attack_params = {'noise_std': 30, 'blur_kernel': 5, 'blur_sigma': 1.5}
            
        elif attack_type == 'scaling_rotation':
            # 缩放+旋转组合攻击
            # 先缩放
            scale = np.random.uniform(0.7, 1.3)
            new_w, new_h = int(w * scale), int(h * scale)
            scaled = cv2.resize(image, (new_w, new_h))
            scaled = cv2.resize(scaled, (w, h))
            # 再旋转
            angle = np.random.uniform(10, 30)
            center = (w // 2, h // 2)
            matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
            attacked_image = cv2.warpAffine(scaled, matrix, (w, h))
            attack_params = {'scale': scale, 'rotation_angle': angle}
            
        else:
            raise ValueError(f"不支持的攻击类型: {attack_type}")
        
        return attacked_image, attack_params
    
    def visualize_attacks(self, original_image_path: str, save_path: str = None):
        """
        可视化所有攻击的效果
        
        Args:
            original_image_path: 原始图像路径
            save_path: 保存路径，如果为None则显示图像
        """
        original_image = cv2.imread(original_image_path)
        if original_image is None:
            raise ValueError(f"无法读取图像: {original_image_path}")
        
        # 转换为RGB用于显示
        original_image_rgb = cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB)
        
        # 计算子图布局
        total_attacks = sum(len(attacks) for attacks in self.available_attacks.values())
        cols = 4
        rows = (total_attacks + 1 + cols - 1) // cols  # +1 for original image
        
        fig, axes = plt.subplots(rows, cols, figsize=(20, 5 * rows))
        if rows == 1:
            axes = axes.reshape(1, -1)
        
        # 显示原始图像
        axes[0, 0].imshow(original_image_rgb)
        axes[0, 0].set_title('原始图像', fontsize=12)
        axes[0, 0].axis('off')
        
        # 显示攻击后的图像
        attack_idx = 1
        for category, attacks in self.available_attacks.items():
            for attack_type in attacks:
                if attack_idx < total_attacks + 1:
                    row = attack_idx // cols
                    col = attack_idx % cols
                    
                    attack_key = f"{category}_{attack_type}"
                    if attack_key in self.attack_images:
                        attack_img = cv2.imread(self.attack_images[attack_key]['path'])
                        attack_img_rgb = cv2.cvtColor(attack_img, cv2.COLOR_BGR2RGB)
                        axes[row, col].imshow(attack_img_rgb)
                        axes[row, col].set_title(f'{category}\n{attack_type}', fontsize=10)
                        axes[row, col].axis('off')
                    else:
                        axes[row, col].text(0.5, 0.5, 'N/A', ha='center', va='center', 
                                          transform=axes[row, col].transAxes)
                        axes[row, col].set_title(f'{category}\n{attack_type}', fontsize=10)
                        axes[row, col].axis('off')
                    
                    attack_idx += 1
        
        # 隐藏多余的子图
        for i in range(attack_idx, rows * cols):
            row = i // cols
            col = i % cols
            axes[row, col].axis('off')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"攻击效果可视化图已保存到: {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def _save_comprehensive_results(self):
        """保存全面的测试结果"""
        results_file = os.path.join(self.output_dir, "comprehensive_test_results.json")
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, ensure_ascii=False, indent=2)
        
        print(f"\n全面测试结果已保存到: {results_file}")
    
    def _generate_comprehensive_report(self):
        """生成全面的测试报告"""
        report = []
        report.append("=" * 80)
        report.append("数字水印鲁棒性全面测试报告")
        report.append("=" * 80)
        report.append(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # 统计信息
        total_attacks = 0
        successful_attacks = 0
        
        for category, attacks in self.test_results.items():
            report.append(f"【{category.upper()} 类别】")
            for attack_type, result in attacks.items():
                total_attacks += 1
                if result.get('status') == 'completed':
                    successful_attacks += 1
                    report.append(f"  ✅ {attack_type}: 攻击完成")
                    if 'attack_params' in result:
                        params_str = ', '.join([f"{k}={v}" for k, v in result['attack_params'].items()])
                        report.append(f"      参数: {params_str}")
                else:
                    report.append(f"  ❌ {attack_type}: {result.get('error_message', '未知错误')}")
            report.append("")
        
        # 总结
        report.append("=" * 80)
        report.append("测试总结")
        report.append("=" * 80)
        report.append(f"总攻击类型数: {total_attacks}")
        report.append(f"成功攻击数: {successful_attacks}")
        report.append(f"成功率: {successful_attacks/total_attacks*100:.1f}%")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        # 保存报告
        report_file = os.path.join(self.output_dir, "comprehensive_test_report.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"全面测试报告已保存到: {report_file}")
        return report_text


def demo_robustness_testing():
    """演示鲁棒性测试功能"""
    
    # 创建测试器
    tester = RobustnessTester()
    
    # 运行全面测试
    print("开始演示鲁棒性测试...")
    
    # 注意：这里需要先有一个嵌入水印的图像
    # 假设我们已经有了一个嵌入水印的图像
    embedded_image_path = "output/embedded_text.png"  # 这个路径需要根据实际情况调整
    
    if os.path.exists(embedded_image_path):
        # 运行测试
        results = tester.run_comprehensive_test(
            image_path=embedded_image_path,
            watermark_shape=111,  # 根据实际水印大小调整
            watermark_type='text'
        )
        
        # 可视化攻击效果
        tester.visualize_attacks(
            original_image_path=embedded_image_path,
            save_path="output/attack_visualization.png"
        )
        
        print("鲁棒性测试演示完成！")
    else:
        print(f"未找到嵌入水印的图像: {embedded_image_path}")
        print("请先运行水印嵌入功能")


if __name__ == "__main__":
    demo_robustness_testing()