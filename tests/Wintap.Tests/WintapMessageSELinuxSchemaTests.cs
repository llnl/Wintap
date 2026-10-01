using System;
using System.Reflection;
using gov.llnl.wintap.collect.models;
using Xunit;

namespace Wintap.Tests
{
    public class WintapMessageSELinuxSchemaTests
    {
        [Theory]
        [InlineData("SELinuxAvc")]
        [InlineData("SELinuxTransition")]
        [InlineData("SELinuxInteraction")]
        [Trait("Category", "sel-04")]
        public void SELinuxMessageTypes_ParseAndRoundTrip(string value)
        {
            var parsed = Enum.Parse<WintapMessage.MessageTypeEnum>(value);

            Assert.Equal(value, parsed.ToString());
        }

        [Theory]
        [InlineData("SELinuxAvc", typeof(WintapMessage.SELinuxAvcData))]
        [InlineData("SELinuxTransition", typeof(WintapMessage.SELinuxTransitionData))]
        [InlineData("SELinuxInteraction", typeof(WintapMessage.SELinuxInteractionData))]
        [Trait("Category", "sel-04")]
        public void SELinuxPayloadProperties_MatchMessageTypeNames(string propertyName, Type expectedType)
        {
            PropertyInfo property = typeof(WintapMessage).GetProperty(propertyName);

            Assert.NotNull(property);
            Assert.Equal(expectedType, property.PropertyType);
            Assert.True(property.GetMethod.IsPublic);
            Assert.True(property.SetMethod.IsPublic);
        }

        [Fact]
        [Trait("Category", "sel-04")]
        public void SELinuxInteraction_DefaultsPreserveCountSemantics()
        {
            var interaction = new WintapMessage.SELinuxInteractionData();

            Assert.Equal(1, interaction.EventCount);
            Assert.False(interaction.Novel);
            Assert.Equal(0, interaction.PolicyEpoch);
        }
    }
}
