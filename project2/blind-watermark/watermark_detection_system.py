#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于数字水印的图片泄露检测系统
作业要求：编程实现图片水印嵌入和提取，并进行鲁棒性测试

作者：[您的姓名]
学号：[您的学号]
课程：[课程名称]
日期：[日期]

功能说明：
1. 水印嵌入：将文本或图片水印嵌入到原始图像中
2. 水印提取：从嵌入水印的图像中提取水印信息
3. 鲁棒性测试：测试水印对抗各种攻击的能力
4. 泄露检测：通过水印验证图像是否被篡改或泄露
"""

import os
import cv2
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import json
from typing import Union, Tuple, List, Dict, Any

# 导入原始的水印核心模块
from blind_watermark import WaterMark
from blind_watermark import att
from blind_watermark.recover import estimate_crop_parameters, recover_crop


class WatermarkDetectionSystem:
    """数字水印检测系统主类"""
    
    def __init__(self, password_img: int = 12345, password_wm: int = 67890):
        """
        初始化水印检测系统
        
        Args:
            password_img: 图像密码，用于图像分块加密
            password_wm: 水印密码，用于水印加密
        """
        self.password_img = password_img
        self.password_wm = password_wm
        self.watermark = WaterMark(password_img=password_img, password_wm=password_wm)
        
        # 记录处理历史
        self.processing_history = []
        self.test_results = {}
        
        print("=" * 60)
        print("基于数字水印的图片泄露检测系统")
        print("=" * 60)
        print(f"图像密码: {password_img}")
        print(f"水印密码: {password_wm}")
        print("=" * 60)
    
    def embed_watermark(self, 
                        original_image_path: str, 
                        watermark_content: Union[str, str], 
                        output_path: str,
                        watermark_type: str = 'text') -> Dict[str, Any]:
        """
        嵌入水印到图像中
        
        Args:
            original_image_path: 原始图像路径
            watermark_content: 水印内容（文本或图片路径）
            output_path: 输出图像路径
            watermark_type: 水印类型 ('text' 或 'image')
            
        Returns:
            包含处理结果的字典
        """
        try:
            print(f"\n开始嵌入{watermark_type}水印...")
            
            # 读取原始图像
            self.watermark.read_img(original_image_path)
            original_img = cv2.imread(original_image_path)
            
            # 读取水印内容
            if watermark_type == 'text':
                self.watermark.read_wm(watermark_content, mode='str')
                watermark_info = f"文本水印: {watermark_content}"
            else:
                self.watermark.read_wm(watermark_content, mode='img')
                watermark_info = f"图片水印: {watermark_content}"
            
            # 嵌入水印
            embedded_img = self.watermark.embed(output_path)
            
            # 记录处理信息
            result = {
                'timestamp': datetime.now().isoformat(),
                'operation': 'embed',
                'original_image': original_image_path,
                'watermark_content': watermark_content,
                'watermark_type': watermark_type,
                'output_path': output_path,
                'watermark_size': len(self.watermark.wm_bit),
                'image_shape': original_img.shape,
                'status': 'success'
            }
            
            self.processing_history.append(result)
            
            print(f"✅ 水印嵌入成功！")
            print(f"   原始图像: {original_image_path}")
            print(f"   水印内容: {watermark_info}")
            print(f"   输出图像: {output_path}")
            print(f"   水印大小: {result['watermark_size']} bits")
            
            return result
            
        except Exception as e:
            error_result = {
                'timestamp': datetime.now().isoformat(),
                'operation': 'embed',
                'status': 'error',
                'error_message': str(e)
            }
            self.processing_history.append(error_result)
            print(f"❌ 水印嵌入失败: {str(e)}")
            return error_result
    
    def extract_watermark(self, 
                         embedded_image_path: str, 
                         watermark_shape: Union[int, Tuple[int, int]], 
                         output_path: str = None,
                         watermark_type: str = 'text') -> Dict[str, Any]:
        """
        从图像中提取水印
        
        Args:
            embedded_image_path: 嵌入水印的图像路径
            watermark_shape: 水印形状（文本为长度，图片为(高度,宽度)）
            output_path: 水印输出路径（仅图片水印需要）
            watermark_type: 水印类型 ('text' 或 'image')
            
        Returns:
            包含提取结果的字典
        """
        try:
            print(f"\n开始提取{watermark_type}水印...")
            
            # 提取水印
            if watermark_type == 'text':
                extracted_wm = self.watermark.extract(
                    filename=embedded_image_path, 
                    wm_shape=watermark_shape, 
                    mode='str'
                )
                watermark_info = f"提取的文本: {extracted_wm}"
            else:
                extracted_wm = self.watermark.extract(
                    filename=embedded_image_path, 
                    wm_shape=watermark_shape, 
                    out_wm_name=output_path, 
                    mode='img'
                )
                watermark_info = f"图片水印已保存到: {output_path}"
            
            # 记录处理信息
            result = {
                'timestamp': datetime.now().isoformat(),
                'operation': 'extract',
                'embedded_image': embedded_image_path,
                'watermark_shape': watermark_shape,
                'watermark_type': watermark_type,
                'extracted_watermark': extracted_wm,
                'output_path': output_path,
                'status': 'success'
            }
            
            self.processing_history.append(result)
            
            print(f"✅ 水印提取成功！")
            print(f"   嵌入图像: {embedded_image_path}")
            print(f"   水印形状: {watermark_shape}")
            print(f"   提取结果: {watermark_info}")
            
            return result
            
        except Exception as e:
            error_result = {
                'timestamp': datetime.now().isoformat(),
                'operation': 'extract',
                'status': 'error',
                'error_message': str(e)
            }
            self.processing_history.append(error_result)
            print(f"❌ 水印提取失败: {str(e)}")
            return error_result
    
    def test_robustness(self, 
                       embedded_image_path: str, 
                       watermark_shape: Union[int, Tuple[int, int]],
                       watermark_type: str = 'text',
                       test_cases: List[str] = None) -> Dict[str, Any]:
        """
        进行鲁棒性测试
        
        Args:
            embedded_image_path: 嵌入水印的图像路径
            watermark_shape: 水印形状
            watermark_type: 水印类型
            test_cases: 测试用例列表，如果为None则测试所有用例
            
        Returns:
            测试结果字典
        """
        if test_cases is None:
            test_cases = [
                'rotation', 'scaling', 'cropping', 'brightness', 
                'contrast', 'noise', 'compression', 'blur'
            ]
        
        print(f"\n开始鲁棒性测试...")
        print(f"测试用例: {', '.join(test_cases)}")
        
        test_results = {}
        original_image = cv2.imread(embedded_image_path)
        
        for test_case in test_cases:
            print(f"\n--- 测试 {test_case} 攻击 ---")
            
            try:
                # 执行攻击
                attacked_image, attack_params = self._apply_attack(
                    original_image, test_case
                )
                
                # 保存攻击后的图像
                attack_output_path = f"output/attacked_{test_case}.png"
                cv2.imwrite(attack_output_path, attacked_image)
                
                # 尝试提取水印
                extraction_result = self.extract_watermark(
                    attack_output_path, watermark_shape, watermark_type=watermark_type
                )
                
                # 记录测试结果
                test_results[test_case] = {
                    'attack_params': attack_params,
                    'attack_output': attack_output_path,
                    'extraction_success': extraction_result['status'] == 'success',
                    'extraction_result': extraction_result
                }
                
                if extraction_result['status'] == 'success':
                    print(f"✅ {test_case} 攻击后水印提取成功")
                else:
                    print(f"❌ {test_case} 攻击后水印提取失败")
                    
            except Exception as e:
                print(f"❌ {test_case} 测试失败: {str(e)}")
                test_results[test_case] = {
                    'status': 'error',
                    'error_message': str(e)
                }
        
        # 保存测试结果
        self.test_results = test_results
        self._save_test_results()
        
        return test_results
    
    def _apply_attack(self, image: np.ndarray, attack_type: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        应用攻击到图像
        
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
            angle = 45
            center = (w // 2, h // 2)
            matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
            attacked_image = cv2.warpAffine(image, matrix, (w, h))
            attack_params = {'angle': angle, 'center': center}
            
        elif attack_type == 'scaling':
            # 缩放攻击
            scale = 0.8
            new_w, new_h = int(w * scale), int(h * scale)
            attacked_image = cv2.resize(image, (new_w, new_h))
            attacked_image = cv2.resize(attacked_image, (w, h))  # 恢复原尺寸
            attack_params = {'scale': scale}
            
        elif attack_type == 'cropping':
            # 裁剪攻击
            crop_ratio = 0.7
            start_x = int(w * (1 - crop_ratio) // 2)
            start_y = int(h * (1 - crop_ratio) // 2)
            end_x = start_x + int(w * crop_ratio)
            end_y = start_y + int(h * crop_ratio)
            attacked_image = image[start_y:end_y, start_x:end_x]
            attacked_image = cv2.resize(attacked_image, (w, h))  # 恢复原尺寸
            attack_params = {'crop_ratio': crop_ratio, 'start': (start_x, start_y), 'end': (end_x, end_y)}
            
        elif attack_type == 'brightness':
            # 亮度攻击
            brightness_factor = 1.3
            attacked_image = cv2.convertScaleAbs(image, alpha=brightness_factor, beta=0)
            attack_params = {'brightness_factor': brightness_factor}
            
        elif attack_type == 'contrast':
            # 对比度攻击
            contrast_factor = 1.5
            attacked_image = cv2.convertScaleAbs(image, alpha=contrast_factor, beta=0)
            attack_params = {'contrast_factor': contrast_factor}
            
        elif attack_type == 'noise':
            # 噪声攻击
            noise_ratio = 0.05
            noise = np.random.normal(0, 25, image.shape).astype(np.uint8)
            attacked_image = cv2.add(image, noise)
            attack_params = {'noise_ratio': noise_ratio}
            
        elif attack_type == 'compression':
            # 压缩攻击
            quality = 50
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
            _, encoded_img = cv2.imencode('.jpg', image, encode_param)
            attacked_image = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
            attack_params = {'quality': quality}
            
        elif attack_type == 'blur':
            # 模糊攻击
            kernel_size = 5
            attacked_image = cv2.GaussianBlur(image, (kernel_size, kernel_size), 0)
            attack_params = {'kernel_size': kernel_size}
            
        else:
            raise ValueError(f"不支持的攻击类型: {attack_type}")
        
        return attacked_image, attack_params
    
    def detect_leakage(self, 
                      original_image_path: str, 
                      suspected_image_path: str,
                      watermark_shape: Union[int, Tuple[int, int]],
                      watermark_type: str = 'text') -> Dict[str, Any]:
        """
        检测图像是否被泄露或篡改
        
        Args:
            original_image_path: 原始图像路径
            suspected_image_path: 可疑图像路径
            watermark_shape: 水印形状
            watermark_type: 水印类型
            
        Returns:
            泄露检测结果
        """
        print(f"\n开始泄露检测...")
        
        try:
            # 从原始图像提取水印
            original_watermark = self.extract_watermark(
                original_image_path, watermark_shape, watermark_type=watermark_type
            )
            
            # 从可疑图像提取水印
            suspected_watermark = self.extract_watermark(
                suspected_image_path, watermark_shape, watermark_type=watermark_type
            )
            
            # 比较水印
            if (original_watermark['status'] == 'success' and 
                suspected_watermark['status'] == 'success'):
                
                if watermark_type == 'text':
                    is_same = (original_watermark['extracted_watermark'] == 
                              suspected_watermark['extracted_watermark'])
                else:
                    # 对于图片水印，比较相似度
                    is_same = self._compare_image_watermarks(
                        original_watermark['extracted_watermark'],
                        suspected_watermark['extracted_watermark']
                    )
                
                if is_same:
                    result = {
                        'leakage_detected': False,
                        'confidence': 'high',
                        'message': '未检测到泄露，水印完全匹配',
                        'original_watermark': original_watermark,
                        'suspected_watermark': suspected_watermark
                    }
                    print("✅ 未检测到泄露")
                else:
                    result = {
                        'leakage_detected': True,
                        'confidence': 'high',
                        'message': '检测到泄露，水印不匹配',
                        'original_watermark': original_watermark,
                        'suspected_watermark': suspected_watermark
                    }
                    print("❌ 检测到泄露！")
            else:
                result = {
                    'leakage_detected': 'unknown',
                    'confidence': 'low',
                    'message': '无法确定是否泄露，水印提取失败',
                    'original_watermark': original_watermark,
                    'suspected_watermark': suspected_watermark
                }
                print("⚠️ 无法确定是否泄露")
            
            return result
            
        except Exception as e:
            error_result = {
                'leakage_detected': 'error',
                'confidence': 'none',
                'message': f'泄露检测失败: {str(e)}',
                'error': str(e)
            }
            print(f"❌ 泄露检测失败: {str(e)}")
            return error_result
    
    def _compare_image_watermarks(self, wm1: np.ndarray, wm2: np.ndarray) -> bool:
        """比较两个图片水印的相似度"""
        if wm1.shape != wm2.shape:
            return False
        
        # 计算结构相似性指数 (SSIM)
        similarity = cv2.matchTemplate(wm1, wm2, cv2.TM_CCOEFF_NORMED)
        max_similarity = np.max(similarity)
        
        # 如果相似度大于0.8，认为水印相同
        return max_similarity > 0.8
    
    def _save_test_results(self):
        """保存测试结果到文件"""
        results_file = "output/robustness_test_results.json"
        os.makedirs("output", exist_ok=True)
        
        # 转换numpy类型为Python原生类型，以便JSON序列化
        serializable_results = self._convert_to_serializable(self.test_results)
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, ensure_ascii=False, indent=2)
        
        print(f"\n测试结果已保存到: {results_file}")
    
    def _convert_to_serializable(self, obj):
        """将对象转换为可JSON序列化的格式"""
        if isinstance(obj, dict):
            return {key: self._convert_to_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_serializable(item) for item in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj
    
    def generate_report(self) -> str:
        """生成测试报告"""
        report = []
        report.append("=" * 60)
        report.append("数字水印鲁棒性测试报告")
        report.append("=" * 60)
        report.append(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"图像密码: {self.password_img}")
        report.append(f"水印密码: {self.password_wm}")
        report.append("")
        
        # 处理历史
        report.append("处理历史:")
        for i, record in enumerate(self.processing_history, 1):
            report.append(f"{i}. {record['operation']} - {record['status']}")
            if record['status'] == 'success':
                if record['operation'] == 'embed':
                    report.append(f"   原始图像: {record['original_image']}")
                    report.append(f"   水印内容: {record['watermark_content']}")
                    report.append(f"   输出图像: {record['output_path']}")
                elif record['operation'] == 'extract':
                    report.append(f"   嵌入图像: {record['embedded_image']}")
                    report.append(f"   提取结果: {record['extracted_watermark']}")
            report.append("")
        
        # 测试结果
        if self.test_results:
            report.append("鲁棒性测试结果:")
            for test_case, result in self.test_results.items():
                if result.get('status') != 'error':
                    success = "✅" if result.get('extraction_success') else "❌"
                    report.append(f"{success} {test_case}: {'成功' if result.get('extraction_success') else '失败'}")
                else:
                    report.append(f"⚠️ {test_case}: 测试失败")
            report.append("")
        
        report.append("=" * 60)
        
        report_text = "\n".join(report)
        
        # 保存报告
        report_file = "output/test_report.txt"
        os.makedirs("output", exist_ok=True)
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"测试报告已保存到: {report_file}")
        return report_text


def main():
    """主函数 - 演示系统功能"""
    
    # 创建输出目录
    os.makedirs("output", exist_ok=True)
    
    # 初始化系统
    system = WatermarkDetectionSystem()
    
    # 示例：文本水印嵌入和提取
    print("\n" + "="*60)
    print("示例1: 文本水印嵌入和提取")
    print("="*60)
    
    # 嵌入水印
    embed_result = system.embed_watermark(
        original_image_path="wyx.png",
        watermark_content="wangan—202200460086",
        output_path="output/embedded_text.png",
        watermark_type="text"
    )
    
    if embed_result['status'] == 'success':
        # 提取水印
        extract_result = system.extract_watermark(
            embedded_image_path="output/embedded_text.png",
            watermark_shape=embed_result['watermark_size'],
            watermark_type="text"
        )
    
    # 示例：鲁棒性测试
    print("\n" + "="*60)
    print("示例2: 鲁棒性测试")
    print("="*60)
    
    if embed_result['status'] == 'success':
        test_results = system.test_robustness(
            embedded_image_path="output/embedded_text.png",
            watermark_shape=embed_result['watermark_size'],
            watermark_type="text",
            test_cases=['rotation', 'scaling', 'brightness', 'noise']
        )
    
    # 生成测试报告
    print("\n" + "="*60)
    print("生成测试报告")
    print("="*60)
    
    report = system.generate_report()
    print(report)
    
    print("\n" + "="*60)
    print("系统演示完成！")
    print("="*60)


if __name__ == "__main__":
    main()
