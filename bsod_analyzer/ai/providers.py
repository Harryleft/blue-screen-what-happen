"""
AI provider implementations.

Supports ZhipuAI (GLM-4.7) for crash analysis.
"""

from abc import ABC, abstractmethod
from typing import Optional
from loguru import logger


class IAIProvider(ABC):
    """AI provider interface."""

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """Send analysis request to AI.

        Args:
            prompt: The prompt to send

        Returns:
            AI response text
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is properly configured."""
        pass


class ZhipuProvider(IAIProvider):
    """ZhipuAI provider for GLM-4.7."""

    def __init__(self, api_key: str, model: str = "glm-4.7"):
        """Initialize ZhipuAI provider.

        Args:
            api_key: ZhipuAI API key
            model: Model name (default: glm-4.7)
        """
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        """Lazy load the ZhipuAI client."""
        if self._client is None:
            try:
                from zhipuai import ZhipuAI
                self._client = ZhipuAI(api_key=self.api_key)
                logger.debug(f"ZhipuAI client initialized with model: {self.model}")
            except ImportError:
                raise RuntimeError(
                    "zhipuai package not found. Install with: pip install zhipuai"
                )
        return self._client

    def analyze(self, prompt: str) -> str:
        """Send analysis request to ZhipuAI.

        Args:
            prompt: The prompt to send

        Returns:
            AI response text
        """
        try:
            client = self._get_client()

            logger.debug(f"Sending request to ZhipuAI (model: {self.model})...")

            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Windows crash dump analysis expert. Provide clear, technical explanations and actionable recommendations.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=2048,
            )

            result = response.choices[0].message.content
            logger.debug("Received response from ZhipuAI")
            return result

        except Exception as e:
            logger.error(f"ZhipuAI request failed: {e}")
            raise RuntimeError(f"AI analysis failed: {e}")

    def is_available(self) -> bool:
        """Check if ZhipuAI is properly configured."""
        return bool(self.api_key)


class AIProviderFactory:
    """Factory for creating AI providers."""

    @staticmethod
    def create(provider_type: str, **kwargs) -> IAIProvider:
        """Create an AI provider instance.

        Args:
            provider_type: Type of provider ("zhipuai")
            **kwargs: Provider-specific arguments

        Returns:
            IAIProvider instance
        """
        if provider_type == "zhipuai":
            api_key = kwargs.get("api_key")
            model = kwargs.get("model", "glm-4.7")
            if not api_key:
                raise ValueError("api_key is required for ZhipuAI provider")
            return ZhipuProvider(api_key=api_key, model=model)
        else:
            raise ValueError(f"Unknown provider type: {provider_type}")

    @staticmethod
    def create_from_config(config) -> Optional[IAIProvider]:
        """Create AI provider from configuration.

        Args:
            config: Config object from utils.config

        Returns:
            IAIProvider instance or None if not configured
        """
        api_key = config.zhipu_api_key
        if not api_key:
            logger.warning("ZHIPU_API_KEY not configured")
            return None

        return ZhipuProvider(api_key=api_key, model=config.ai_model)
