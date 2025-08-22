# Hybrid IaC EKS CI/CD

이 저장소는 **AWS와 On-Premise 하이브리드 환경**의  
**인프라(IaC)**와 **CI/CD**를 관리하기 위한 개인 기록용 Repository입니다.  
검증된 결과물은 팀 Repository에 반영됩니다.

## 목차

1. [목적](#1-목적)
2. [폴더 구조](#2-폴더-구조)

## 1. 목적

- 인프라 및 FE Infra, CI/CD 구성 실험
- AWS와 On-Premise 환경 혼합(Hybrid) 아키텍처 시나리오 검증
- IaC 관리 및 실습
- 실험/검증 과정 기록 → 학습 및 최종 정리 후 팀 Repository 반영

## 2. 폴더 구조

- `docs/` : 아키텍처 개요, 결정(ADR), 변경 로그(Change-log), 운영 가이드(Runbook)
- `iac/` : Terraform/Helm 기반 IaC 코드
  - `envs/lab` : 개인 실험 (실패/테스트 포함)
  - `envs/dev` : 검증 완료 → 팀 반영 대상
- `pipelines/` : CI/CD 정의 및 GitHub Actions 워크플로
- `scripts/` : 반복작업 자동화 (Terraform plan/apply 등)
